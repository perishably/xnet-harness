"""Final ten independent multi-file repair fixtures for the frozen SWE-style set."""


def add_additions(add, _f, _p):
    cat = "configuration-validation"
    add(cat, "profile-sections", "resolve_profile(defaults, profiles, selected)",
        "defaults and each named profile map section names to dictionaries of JSON leaf values. Copy defaults, then merge the selected profile within each section, preserving default siblings. Unknown profiles use defaults; new sections are allowed.",
        "Selecting a profile loses default settings in partially overridden sections.", """
        def merge_section(base, override):
            return dict(override)
        """, """
        from helpers import merge_section
        def resolve_profile(defaults, profiles, selected):
            result = {name: dict(values) for name, values in defaults.items()}
            for name, values in profiles.get(selected, {}).items():
                result[name] = merge_section(defaults.get(name, {}), values)
            return result
        """, [
            _f([{"svc": {"host": "local", "port": 80}}, {"prod": {"svc": {"port": 81}}}, "prod"], {"svc": {"host": "local", "port": 81}}),
            _p([{"svc": {"port": 80}}, {}, "prod"], {"svc": {"port": 80}}),
            _f([{"a": {"x": 1, "y": 2}, "b": {"v": 3}}, {"p": {"a": {"y": 4}, "b": {}}}, "p"], {"a": {"x": 1, "y": 4}, "b": {"v": 3}}),
            _f([{"s": {"enabled": True}}, {"p": {"s": {}}}, "p"], {"s": {"enabled": True}}),
            _p([{}, {"p": {"new": {"k": 1}}}, "p"], {"new": {"k": 1}}),
            _p([{"s": {"x": 1}}, {"other": {"s": {"x": 2}}}, "unknown"], {"s": {"x": 1}})])
    add(cat, "inherited-flags", "feature_enabled(profile, defaults, name)",
        "Profile flag strings on/off/inherit are case insensitive. Missing profile flags mean inherit. Inherit returns defaults.get(name,False), whose supplied values are booleans. Invalid tokens raise ValueError.",
        "Inherited feature flags ignore an enabled default.", """
        def parse_flag(value, default):
            token = value.lower()
            if token == 'on':
                return True
            if token == 'off':
                return False
            if token == 'inherit':
                return False
            raise ValueError('unknown flag')
        """, """
        from helpers import parse_flag
        def feature_enabled(profile, defaults, name):
            return parse_flag(profile.get(name, 'inherit'), defaults.get(name, False))
        """, [_f([{"x": "inherit"}, {"x": True}, "x"], True),
              _p([{"x": "off"}, {"x": True}, "x"], False),
              _f([{}, {"z": True}, "z"], True),
              _f([{"x": "INHERIT"}, {"x": True}, "x"], True),
              _p([{"x": "inherit"}, {"x": False}, "x"], False),
              _p([{"x": "on"}, {}, "x"], True)])
    add(cat, "capped-retry-schedule", "retry_schedule(base, multiplier, count, cap)",
        "All inputs are integers: base/count/cap nonnegative, multiplier>=1. Return count delays. Attempt n starts at zero and has delay min(base*multiplier**n,cap). Apply the cap to each resulting delay.",
        "Configured retry delays exceed their maximum after the first attempt.", """
        def retry_delay(base, multiplier, attempt, cap):
            return min(base, cap) * multiplier ** attempt
        """, """
        from helpers import retry_delay
        def retry_schedule(base, multiplier, count, cap):
            return [retry_delay(base, multiplier, attempt, cap) for attempt in range(count)]
        """, [_f([3, 2, 4, 10], [3, 6, 10, 10]), _p([3, 2, 0, 10], []),
              _f([8, 3, 2, 5], [5, 5]), _f([2, 3, 3, 8], [2, 6, 8]),
              _p([1, 2, 3, 8], [1, 2, 4]), _p([9, 1, 4, 4], [4, 4, 4, 4])])
    add(cat, "inclusive-endpoint-ranges", "usable_endpoints(endpoints, ranges)",
        "Pure configuration data only: endpoints have name, integer port and boolean enabled. ranges are [low,high] inclusive at BOTH ends. Return names of enabled endpoints within any range, preserving input order. No networking occurs.",
        "Configuration filtering excludes enabled endpoints at the range's upper bound.", """
        def in_ranges(port, ranges):
            return any(low <= port < high for low, high in ranges)
        """, """
        from helpers import in_ranges
        def usable_endpoints(endpoints, ranges):
            return [item['name'] for item in endpoints if item['enabled'] and in_ranges(item['port'], ranges)]
        """, [
            _f([[{"name": "edge", "port": 20, "enabled": True}], [[10, 20]]], ["edge"]),
            _p([[{"name": "mid", "port": 15, "enabled": True}], [[10, 20]]], ["mid"]),
            _f([[{"name": "point", "port": 30, "enabled": True}], [[30, 30]]], ["point"]),
            _f([[{"name": "upper", "port": 18, "enabled": True}, {"name": "disabled", "port": 18, "enabled": False}, {"name": "low", "port": 10, "enabled": True}], [[10, 18]]], ["upper", "low"]),
            _p([[{"name": "disabled", "port": 20, "enabled": False}], [[10, 20]]], []),
            _p([[{"name": "outside", "port": 19, "enabled": True}], [[10, 18]]], [])])
    add(cat, "conditional-required-fields", "invalid_sections(sections)",
        "Each section has name, boolean enabled, required (list of field names), and values (dictionary). Only enabled sections require their named fields to be present. Return names of enabled sections missing any required field, in input order. Presence, not truthiness, satisfies a field.",
        "Disabled sections are incorrectly rejected for missing settings.", """
        def missing_required(values, names):
            return [name for name in names if name not in values]
        """, """
        from helpers import missing_required
        def invalid_sections(sections):
            return [section['name'] for section in sections if missing_required(section['values'], section['required'])]
        """, [
            _f([[{"name": "off", "enabled": False, "required": ["path"], "values": {}}]], []),
            _p([[{"name": "on", "enabled": True, "required": ["path"], "values": {}}]], ["on"]),
            _f([[{"name": "off", "enabled": False, "required": ["x"], "values": {}}, {"name": "on", "enabled": True, "required": ["y"], "values": {}}]], ["on"]),
            _f([[{"name": "a", "enabled": False, "required": ["x"], "values": {}}, {"name": "b", "enabled": False, "required": ["y"], "values": {}}]], []),
            _p([[{"name": "off", "enabled": False, "required": ["x"], "values": {"x": 0}}]], []),
            _p([[{"name": "on", "enabled": True, "required": ["x"], "values": {"x": False}}]], [])])

    cat = "relational-transforms"
    add(cat, "left-join-preservation", "attach_labels(rows, labels)",
        "rows have id and value. labels maps ids to strings. Return [id,value,label] for EVERY input row in order; unmatched ids have label None. ids are strings and may repeat.",
        "Attaching labels drops source rows without a matching label.", """
        def label_for(labels, row_id):
            return labels.get(row_id)
        """, """
        from helpers import label_for
        def attach_labels(rows, labels):
            return [[row['id'], row['value'], label_for(labels, row['id'])] for row in rows if row['id'] in labels]
        """, [
            _f([[{"id": "a", "value": 3}, {"id": "b", "value": 4}], {"a": "A"}], [["a", 3, "A"], ["b", 4, None]]),
            _p([[{"id": "a", "value": 3}], {"a": "A"}], [["a", 3, "A"]]),
            _f([[{"id": "z", "value": 8}], {}], [["z", 8, None]]),
            _f([[{"id": "x", "value": 1}, {"id": "x", "value": 2}], {"y": "Y"}], [["x", 1, None], ["x", 2, None]]),
            _p([[], {"a": "A"}], []),
            _p([[{"id": "b", "value": 0}, {"id": "a", "value": 1}], {"a": "A", "b": "B"}], [["b", 0, "B"], ["a", 1, "A"]])])
    add(cat, "join-multiplicity", "matching_pairs(left, right)",
        "left/right rows have key and value. Return [left.value,right.value] for each equal-key pair, preserving left input order and, within a left row, right input order. Retain duplicate-key rows; unmatched rows produce no pair.",
        "Joining tables silently discards earlier right-hand matches with the same key.", """
        def index_values(rows):
            return {row['key']: [row['value']] for row in rows}
        """, """
        from helpers import index_values
        def matching_pairs(left, right):
            index = index_values(right)
            return [[row['value'], value] for row in left for value in index.get(row['key'], [])]
        """, [
            _f([[{"key": "k", "value": "L"}], [{"key": "k", "value": "R1"}, {"key": "k", "value": "R2"}]], [["L", "R1"], ["L", "R2"]]),
            _p([[{"key": "k", "value": "L"}], [{"key": "k", "value": "R"}]], [["L", "R"]]),
            _f([[{"key": "a", "value": 1}, {"key": "a", "value": 2}], [{"key": "a", "value": 3}, {"key": "a", "value": 4}]], [[1, 3], [1, 4], [2, 3], [2, 4]]),
            _f([[{"key": "b", "value": 5}], [{"key": "b", "value": 7}, {"key": "a", "value": 9}, {"key": "b", "value": 8}]], [[5, 7], [5, 8]]),
            _p([[], [{"key": "x", "value": 2}]], []),
            _p([[{"key": "x", "value": 1}], [{"key": "y", "value": 2}]], [])])
    add(cat, "as-of-join", "historical_values(observations, history)",
        "Observations have key and integer at; history rows have key, integer at and JSON value. For each observation, return the value of the same-key history row with greatest at<=observation.at, or None if none qualifies. Preserve observation order; history is unsorted. Each key has unique history timestamps.",
        "Historical joins attach future values to earlier observations.", """
        def latest_record(candidates, at):
            return max(candidates, key=lambda record: record['at']) if candidates else None
        """, """
        from helpers import latest_record
        def historical_values(observations, history):
            result = []
            for observation in observations:
                candidates = [record for record in history if record['key'] == observation['key']]
                record = latest_record(candidates, observation['at'])
                result.append(record['value'] if record is not None else None)
            return result
        """, [
            _f([[{"key": "a", "at": 5}], [{"key": "a", "at": 3, "value": "old"}, {"key": "a", "at": 8, "value": "new"}]], ["old"]),
            _p([[{"key": "a", "at": 10}], [{"key": "a", "at": 3, "value": "old"}, {"key": "a", "at": 8, "value": "new"}]], ["new"]),
            _f([[{"key": "a", "at": 1}], [{"key": "a", "at": 2, "value": 9}]], [None]),
            _f([[{"key": "b", "at": 4}, {"key": "a", "at": 6}], [{"key": "a", "at": 9, "value": 3}, {"key": "b", "at": 4, "value": 7}, {"key": "a", "at": 6, "value": 2}, {"key": "b", "at": 5, "value": 8}]], [7, 2]),
            _p([[{"key": "a", "at": 5}], []], [None]),
            _p([[{"key": "a", "at": 2}, {"key": "z", "at": 9}], [{"key": "a", "at": 2, "value": 0}]], [0, None])])
    add(cat, "composite-anti-join", "unmatched_records(rows, exclusions)",
        "Rows have tenant,id,value. Exclusions have tenant,id. Exclude a row only when BOTH tenant and id match an exclusion; retain all other rows unchanged in input order. Inputs use string tenants and ids.",
        "An exclusion for one tenant removes records owned by other tenants with the same id.", """
        def excluded_keys(exclusions):
            return {item['id'] for item in exclusions}
        """, """
        from helpers import excluded_keys
        def unmatched_records(rows, exclusions):
            blocked = excluded_keys(exclusions)
            return [row for row in rows if row['id'] not in blocked]
        """, [
            _f([[{"tenant": "a", "id": "1", "value": 2}], [{"tenant": "b", "id": "1"}]], [{"tenant": "a", "id": "1", "value": 2}]),
            _p([[{"tenant": "a", "id": "1", "value": 2}], [{"tenant": "a", "id": "1"}]], []),
            _f([[{"tenant": "a", "id": "x", "value": 1}, {"tenant": "b", "id": "x", "value": 2}], [{"tenant": "a", "id": "x"}]], [{"tenant": "b", "id": "x", "value": 2}]),
            _f([[{"tenant": "z", "id": "2", "value": 3}, {"tenant": "z", "id": "1", "value": 4}], [{"tenant": "a", "id": "2"}, {"tenant": "b", "id": "1"}]], [{"tenant": "z", "id": "2", "value": 3}, {"tenant": "z", "id": "1", "value": 4}]),
            _p([[], [{"tenant": "a", "id": "1"}]], []),
            _p([[{"tenant": "a", "id": "1", "value": 2}], [{"tenant": "a", "id": "2"}]], [{"tenant": "a", "id": "1", "value": 2}])])
    add(cat, "pivot-cell-sum", "pivot_amounts(rows)",
        "Rows have row (string), column (string), amount (integer). Return nested row=>column=>sum(amount) for each cell. Repeated cells accumulate, including negative amounts. Empty input gives {}. Do not invent absent cells.",
        "Pivoting transactions overwrites repeated cells instead of accumulating their amounts.", """
        def add_cell(table, row, column, amount):
            table.setdefault(row, {})[column] = amount
        """, """
        from helpers import add_cell
        def pivot_amounts(rows):
            result = {}
            for item in rows:
                add_cell(result, item['row'], item['column'], item['amount'])
            return result
        """, [
            _f([[{"row": "a", "column": "x", "amount": 2}, {"row": "a", "column": "x", "amount": 3}]], {"a": {"x": 5}}),
            _p([[{"row": "a", "column": "x", "amount": 2}, {"row": "a", "column": "y", "amount": 3}]], {"a": {"x": 2, "y": 3}}),
            _f([[{"row": "b", "column": "z", "amount": 10}, {"row": "b", "column": "z", "amount": -4}]], {"b": {"z": 6}}),
            _f([[{"row": "a", "column": "x", "amount": 1}, {"row": "b", "column": "x", "amount": 2}, {"row": "a", "column": "x", "amount": 4}]], {"a": {"x": 5}, "b": {"x": 2}}),
            _p([[]], {}),
            _p([[{"row": "a", "column": "x", "amount": 0}, {"row": "b", "column": "x", "amount": -2}]], {"a": {"x": 0}, "b": {"x": -2}})])
