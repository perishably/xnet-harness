"""Fifty controlled local repair tasks, not official SWE-bench submissions.

Cases are evaluator-only. Use ``public_task`` for model input; no repaired
source or gold patch is authored or stored here. Seed changes task order only.
"""
from __future__ import annotations

import random
import textwrap
from typing import Any

DEFAULT_SEED = 20261004
PUBLIC_FIELDS = ("task_id", "category", "issue", "path", "buggy_source", "function_name", "api_contract")


def _case(kind, args, expected=None, *, kwargs=None, raises=None):
    case = {"args": args, "kwargs": kwargs or {}, "case_type": kind, "hidden": True}
    case["raises" if raises else "expected"] = raises if raises else expected
    return case


def _f(args, expected=None, **options):
    return _case("F2P", args, expected, **options)


def _p(args, expected=None, **options):
    return _case("P2P", args, expected, **options)


def _task(category, slug, signature, contract, issue, source, cases):
    function = signature.split("(", 1)[0]
    identifier = category + "--" + slug
    return {"task_id": identifier, "category": category,
            "issue": issue + " Return the complete repaired module, preserving its public API.",
            "path": "work/oroboros-projects/repair-" + identifier + "/module.py",
            "buggy_source": textwrap.dedent(source).strip() + "\n",
            "function_name": function,
            "api_contract": {"signature": signature, "requirements": contract,
                             "replacement_limit_bytes": 8192, "dependencies": "Python builtins only"},
            "cases": [{**case, "name": function, "case_id": identifier + "-" + str(index)}
                      for index, case in enumerate(cases, 1)]}


def _tasks():
    tasks = []
    def add(category, slug, signature, contract, issue, source, cases):
        tasks.append(_task(category, slug, signature, contract, issue, source, cases))

    cat = "parsing-validation"
    add(cat, "strict-integer", "parse_integer(text)",
        "Accept optional leading +/- and ASCII digits only; reject whitespace, empty/sign-only text and other characters with ValueError.",
        "The integer parser accepts padded input that the wire format forbids.", """
        def parse_integer(text):
            return int(text.strip())
        """, [_f([" 12"], raises="ValueError"), _f(["12 "], raises="ValueError"),
              _p(["-17"], -17), _p(["+8"], 8)])
    add(cat, "csv-fields", "parse_fields(line)",
        "Split a comma-delimited line without quoting support; strip surrounding whitespace from each field, preserving empty fields.",
        "CSV-like fields retain delimiter-adjacent whitespace.", """
        def parse_fields(line):
            return line.strip().split(',')
        """, [_f(["one, two ,three"], ["one", "two", "three"]),
              _f(["a, ,b"], ["a", "", "b"]), _p(["a,,b"], ["a", "", "b"]), _p([""], [""])])
    add(cat, "boolean-token", "parse_boolean(text)",
        "Case-insensitively parse true/false after stripping whitespace; all other tokens raise ValueError.",
        "The false token is parsed as true because nonempty strings are truthy.", """
        def parse_boolean(text):
            token = text.strip().lower()
            if token not in ['true', 'false']:
                raise ValueError('boolean token required')
            return bool(token)
        """, [_f(["false"], False), _f([" FALSE "], False), _p(["True"], True), _p(["yes"], raises="ValueError")])
    add(cat, "semantic-version", "parse_version(text)",
        "Accept exactly three nonempty decimal components separated by dots; return their integer list, otherwise raise ValueError.",
        "Version parsing silently accepts missing or extra components.", """
        def parse_version(text):
            parts = text.split('.')
            if any(not part.isdigit() for part in parts):
                raise ValueError('numeric components required')
            return [int(part) for part in parts]
        """, [_f(["1.2"], raises="ValueError"), _f(["1.2.3.4"], raises="ValueError"),
              _p(["2.10.3"], [2, 10, 3]), _p(["1.x.0"], raises="ValueError")])
    add(cat, "balanced-delimiters", "balanced(text)",
        "Return whether (), [] and {} are correctly nested; ignore other characters.",
        "Balanced delimiters are counted without checking nesting order.", """
        def balanced(text):
            return all(text.count(left) == text.count(right)
                       for left, right in [('(', ')'), ('[', ']'), ('{', '}')])
        """, [_f(["([)]"], False), _f([")("], False), _p(["a{b[c(d)]}"], True), _p(["(("], False)])

    cat = "collections"
    add(cat, "stable-unique", "stable_unique(values)",
        "Return distinct comparable values in order of first occurrence.",
        "Deduplication sorts values and destroys encounter order.", """
        def stable_unique(values):
            return sorted(set(values))
        """, [_f([[3, 1, 3, 2]], [3, 1, 2]), _f([["b", "a", "b"]], ["b", "a"]),
              _p([[1, 2, 2]], [1, 2]), _p([[]], [])])
    add(cat, "occurrence-counts", "occurrence_counts(values)",
        "Return a dictionary mapping each string value to its occurrence count.",
        "The frequency accumulator overwrites counts instead of incrementing them.", """
        def occurrence_counts(values):
            counts = {}
            for value in values:
                counts[value] = 1
            return counts
        """, [_f([["a", "b", "a"]], {"a": 2, "b": 1}), _f([["x", "x", "x"]], {"x": 3}),
              _p([["a", "b"]], {"a": 1, "b": 1}), _p([[]], {})])
    add(cat, "multiset-intersection", "multiset_intersection(left, right)",
        "Return left-order matches, consuming each right-side occurrence at most once.",
        "Intersection repeatedly reuses one right-side occurrence.", """
        def multiset_intersection(left, right):
            return [value for value in left if value in right]
        """, [_f([[1, 1, 2], [1, 2]], [1, 2]), _f([["x", "x"], ["x"]], ["x"]),
              _p([[3, 1], [1, 3]], [3, 1]), _p([[], [1]], [])])
    add(cat, "normalized-rotation", "rotate_left(values, steps)",
        "Rotate left by any integer steps modulo the length; negative steps rotate right; empty input returns [].",
        "Rotation fails to normalize steps larger than the collection.", """
        def rotate_left(values, steps):
            return values[steps:] + values[:steps]
        """, [_f([[1, 2, 3], 4], [2, 3, 1]), _f([[1, 2, 3], -4], [3, 1, 2]),
              _p([[1, 2, 3], 1], [2, 3, 1]), _p([[], 7], [])])
    add(cat, "grouped-pairs", "group_pairs(pairs)",
        "Group [string-key, value] pairs into lists in encounter order, preserving duplicate values.",
        "Grouping loses all but the last value for repeated keys.", """
        def group_pairs(pairs):
            grouped = {}
            for key, value in pairs:
                grouped[key] = [value]
            return grouped
        """, [_f([[["a", 1], ["b", 2], ["a", 3]]], {"a": [1, 3], "b": [2]}),
              _f([[["x", 1], ["x", 1]]], {"x": [1, 1]}), _p([[["a", 4]]], {"a": [4]}), _p([[]], {})])

    cat = "text-processing"
    add(cat, "literal-replacement", "replace_token(text, token, replacement)",
        "Replace exact whitespace-delimited tokens only; normalize separating whitespace to one space.",
        "Token replacement also rewrites substrings inside unrelated words.", """
        def replace_token(text, token, replacement):
            return ' '.join(text.replace(token, replacement).split())
        """, [_f(["cat scatter cat", "cat", "dog"], "dog scatter dog"),
              _f(["on only", "on", "off"], "off only"), _p(["cat cat", "cat", "dog"], "dog dog"),
              _p(["  bird  ", "cat", "dog"], "bird")])
    add(cat, "leading-prefix", "remove_prefix(text, prefix)",
        "Remove at most one matching leading prefix; never remove later occurrences; empty prefix leaves text unchanged.",
        "Prefix removal uses global replacement and deletes internal occurrences.", """
        def remove_prefix(text, prefix):
            return text.replace(prefix, '')
        """, [_f(["pre-middle-pre-end", "pre-"], "middle-pre-end"),
              _f(["middle-pre-end", "pre-"], "middle-pre-end"), _p(["pre-name", "pre-"], "name"), _p(["abc", ""], "abc")])
    add(cat, "common-prefix", "common_prefix(words)",
        "Return the longest common leading string; an empty list returns ''.",
        "The prefix scan reads beyond shorter words.", """
        def common_prefix(words):
            if not words:
                return ''
            prefix = ''
            for index in range(len(words[0])):
                if any(word[index] != words[0][index] for word in words):
                    break
                prefix += words[0][index]
            return prefix
        """, [_f([["flower", "flow"]], "flow"), _f([["abc", ""]], ""),
              _p([["car", "cat"]], "ca"), _p([[]], "")])
    add(cat, "empty-line-retention", "normalize_lines(text)",
        "Normalize CRLF to LF, split on LF and strip each line while preserving every empty line, including trailing empties.",
        "Line normalization removes empty lines that carry paragraph structure.", r"""
        def normalize_lines(text):
            return [line.strip() for line in text.replace('\r\n', '\n').split('\n') if line.strip()]
        """, [_f(["a\n\nb\n"], ["a", "", "b", ""]), _f([""], [""]),
              _p([" a\r\n b "], ["a", "b"]), _p(["only"], ["only"])])
    add(cat, "whitespace-slug", "slug_words(text)",
        "Lowercase whitespace-separated words and join with a single dash; ignore leading, trailing and repeated whitespace.",
        "Slug creation turns repeated whitespace into repeated separators.", """
        def slug_words(text):
            return text.strip().lower().replace(' ', '-')
        """, [_f(["  Two   Words  "], "two-words"), _f(["A\tB"], "a-b"),
              _p(["Hello World"], "hello-world"), _p([""], "")])

    cat = "datetime-calendar"
    add(cat, "gregorian-leap", "is_leap(year)",
        "For positive Gregorian years, leap years are divisible by 4 except centuries not divisible by 400.",
        "Century years are incorrectly treated as leap years.", """
        def is_leap(year):
            return year % 4 == 0
        """, [_f([1900], False), _f([2100], False), _p([2000], True), _p([2023], False)])
    add(cat, "month-successor", "next_month(year, month)",
        "For month 1..12, return [year, month] for the next calendar month.",
        "Advancing December produces month 13 without advancing the year.", """
        def next_month(year, month):
            return [year, month + 1]
        """, [_f([2024, 12], [2025, 1]), _f([1999, 12], [2000, 1]),
              _p([2024, 1], [2024, 2]), _p([2024, 11], [2024, 12])])
    add(cat, "leap-ordinal", "day_of_year(year, month, day)",
        "For a valid Gregorian date, return its one-based ordinal within that year.",
        "Dates after February ignore the extra day in leap years.", """
        def day_of_year(year, month, day):
            lengths = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
            return sum(lengths[:month - 1]) + day
        """, [_f([2024, 3, 1], 61), _f([2000, 12, 31], 366),
              _p([2023, 3, 1], 60), _p([2024, 2, 29], 60)])
    add(cat, "clock-wrapping", "shift_clock(hour, minute, delta)",
        "For a valid 24-hour clock and any integer minute delta, return normalized [hour, minute] modulo one day.",
        "Minute arithmetic does not wrap the hour at midnight.", """
        def shift_clock(hour, minute, delta):
            total = hour * 60 + minute + delta
            return [total // 60, total % 60]
        """, [_f([23, 50, 20], [0, 10]), _f([0, 5, -10], [23, 55]),
              _p([10, 15, 30], [10, 45]), _p([10, 50, 20], [11, 10])])
    add(cat, "date-key-order", "sort_dates(dates)",
        "Sort valid DD/MM/YYYY strings chronologically, returning the original strings; duplicate dates may appear.",
        "Date strings are sorted lexically instead of by year, month and day.", """
        def sort_dates(dates):
            return sorted(dates)
        """, [_f([["01/01/2025", "31/12/2024"]], ["31/12/2024", "01/01/2025"]),
              _f([["10/02/2024", "02/03/2024"]], ["10/02/2024", "02/03/2024"]),
              _p([["02/01/2024", "01/01/2024"]], ["01/01/2024", "02/01/2024"]), _p([[]], [])])

    cat = "arithmetic"
    add(cat, "ceiling-division", "ceil_div(total, size)",
        "For total >=0 and size >0 integers, return the number of size-sized containers needed.",
        "Partial containers are omitted by integer division.", """
        def ceil_div(total, size):
            return total // size
        """, [_f([7, 3], 3), _f([1, 8], 1), _p([9, 3], 3), _p([0, 3], 0)])
    add(cat, "percentage-discount", "discount_price(price, percent)",
        "For nonnegative price and percent in 0..100, return the discounted numeric price without rounding.",
        "Discount percentages are subtracted as currency amounts.", """
        def discount_price(price, percent):
            return price - percent
        """, [_f([80, 25], 60.0), _f([40, 50], 20.0), _p([100, 20], 80.0), _p([19, 0], 19.0)])
    add(cat, "compound-growth", "compound(principal, rate, years)",
        "Return principal compounded once per year at fractional rate for a nonnegative integer number of years.",
        "Multi-year growth uses simple rather than compound interest.", """
        def compound(principal, rate, years):
            return principal * (1 + rate * years)
        """, [_f([100, 0.5, 2], 225.0), _f([8, 1, 3], 64), _p([100, 0.5, 1], 150.0), _p([100, 0.2, 0], 100.0)])
    add(cat, "signed-distance", "manhattan(left, right)",
        "For same-length numeric coordinate lists, sum absolute coordinate differences.",
        "Opposite signed coordinate differences cancel each other.", """
        def manhattan(left, right):
            return abs(sum(a - b for a, b in zip(left, right)))
        """, [_f([[1, 0], [0, 1]], 2), _f([[3, 1], [1, 4]], 5),
              _p([[3, 4], [0, 0]], 7), _p([[], []], 0)])
    add(cat, "cent-allocation", "allocate_cents(total, count)",
        "Split nonnegative integer cents among count>0 recipients; give leftover cents to the earliest recipients; preserve total.",
        "Allocation discards the integer-division remainder.", """
        def allocate_cents(total, count):
            return [total // count for index in range(count)]
        """, [_f([10, 3], [4, 3, 3]), _f([2, 4], [1, 1, 0, 0]), _p([12, 3], [4, 4, 4]), _p([0, 2], [0, 0])])

    cat = "boundaries-ranges"
    add(cat, "touching-intervals", "merge_intervals(intervals)",
        "Merge sorted [start,end] closed intervals whenever they overlap or touch; return fresh interval lists.",
        "Intervals sharing an endpoint remain unnecessarily split.", """
        def merge_intervals(intervals):
            merged = []
            for start, end in intervals:
                if merged and start < merged[-1][1]:
                    merged[-1][1] = max(merged[-1][1], end)
                else:
                    merged.append([start, end])
            return merged
        """, [_f([[[1, 3], [3, 5]]], [[1, 5]]), _f([[[0, 1], [1, 1], [1, 2]]], [[0, 2]]),
              _p([[[1, 4], [2, 5], [8, 9]]], [[1, 5], [8, 9]]), _p([[]], [])])
    add(cat, "one-based-page", "page(values, number, size)",
        "Return a page with number>=1 and size>=1 using one-based page numbers; beyond-end pages are empty.",
        "Pagination treats the documented page number as zero-based.", """
        def page(values, number, size):
            start = number * size
            return values[start:start + size]
        """, [_f([[1, 2, 3, 4, 5], 1, 2], [1, 2]), _f([[1, 2, 3, 4, 5], 3, 2], [5]),
              _p([[1, 2], 4, 2], []), _p([[], 1, 3], [])])
    add(cat, "zero-length-suffix", "take_last(values, count)",
        "For count>=0, return at most count trailing values; count=0 returns [], preserving order.",
        "Python's negative-zero slice returns the whole collection for a zero-size request.", """
        def take_last(values, count):
            return values[-count:]
        """, [_f([[1, 2, 3], 0], []), _f([["x"], 0], []), _p([[1, 2, 3], 2], [2, 3]), _p([[1, 2], 7], [1, 2])])
    add(cat, "grid-neighbors", "neighbors(row, column, rows, columns)",
        "Return valid four-neighbor [row,column] coordinates in up,right,down,left order; inputs identify an in-bounds cell.",
        "Neighbor filtering checks upper limits but permits negative coordinates.", """
        def neighbors(row, column, rows, columns):
            points = [[row - 1, column], [row, column + 1], [row + 1, column], [row, column - 1]]
            return [[r, c] for r, c in points if r < rows and c < columns]
        """, [_f([0, 0, 2, 2], [[0, 1], [1, 0]]), _f([0, 1, 1, 3], [[0, 2], [0, 0]]),
              _p([1, 1, 3, 3], [[0, 1], [1, 2], [2, 1], [1, 0]]), _p([2, 2, 3, 3], [[1, 2], [2, 1]])])
    add(cat, "closed-range", "closed_range(start, stop, step=1)",
        "Return integer progression including stop when aligned, for nonzero step; return [] if step points away from stop.",
        "The closed range incorrectly excludes its aligned endpoint.", """
        def closed_range(start, stop, step=1):
            return list(range(start, stop, step))
        """, [_f([1, 5, 2], [1, 3, 5]), _f([5, 1], [5, 3, 1], kwargs={"step": -2}),
              _p([1, 6, 2], [1, 3, 5]), _p([5, 1, 2], [])])

    cat = "ordering-search"
    add(cat, "binary-endpoint", "binary_find(values, target)",
        "Search a sorted list of unique integers; return its index or -1 when absent.",
        "Binary search exits before examining the final remaining position.", """
        def binary_find(values, target):
            low, high = 0, len(values) - 1
            while low < high:
                middle = (low + high) // 2
                if values[middle] == target:
                    return middle
                if values[middle] < target:
                    low = middle + 1
                else:
                    high = middle - 1
            return -1
        """, [_f([[1, 3, 5], 5], 2), _f([[7], 7], 0), _p([[1, 3, 5], 3], 1), _p([[1, 3, 5], 2], -1)])
    add(cat, "right-insertion", "insertion_right(values, value)",
        "Return the insertion index after all equal values in a sorted list.",
        "Duplicate values are inserted before equals instead of after them.", """
        def insertion_right(values, value):
            index = 0
            while index < len(values) and values[index] < value:
                index += 1
            return index
        """, [_f([[1, 2, 2, 4], 2], 3), _f([[3, 3], 3], 2), _p([[1, 4], 2], 1), _p([[], 5], 0)])
    add(cat, "merge-remainders", "merge_sorted(left, right)",
        "Merge two ascending numeric lists, retaining every element and duplicate; do not mutate inputs.",
        "Sorted merge drops the unconsumed left tail when the right input ends.", """
        def merge_sorted(left, right):
            output = []
            i, j = 0, 0
            while i < len(left) and j < len(right):
                if left[i] <= right[j]:
                    output.append(left[i])
                    i += 1
                else:
                    output.append(right[j])
                    j += 1
            return output + right[j:]
        """, [_f([[2, 4], [1, 3]], [1, 2, 3, 4]), _f([[1, 2], []], [1, 2]),
              _p([[1, 3], [2, 4]], [1, 2, 3, 4]), _p([[], [1, 2]], [1, 2])])
    add(cat, "stable-priority", "sort_priority(items)",
        "Sort [numeric-priority,label] items by ascending priority while preserving input order among ties.",
        "The comparison swaps ties and makes the priority sort unstable.", """
        def sort_priority(items):
            result = [[priority, label] for priority, label in items]
            for end in range(len(result) - 1, 0, -1):
                for index in range(end):
                    if result[index][0] >= result[index + 1][0]:
                        result[index], result[index + 1] = result[index + 1], result[index]
            return result
        """, [_f([[[1, "a"], [1, "b"]]], [[1, "a"], [1, "b"]]),
              _f([[[2, "z"], [1, "a"], [1, "b"]]], [[1, "a"], [1, "b"], [2, "z"]]),
              _p([[[2, "b"], [1, "a"]]], [[1, "a"], [2, "b"]]), _p([[]], [])])
    add(cat, "competition-rank", "competition_ranks(scores)",
        "For descending scores, return competition ranks: tied scores share rank and later ranks skip their positions.",
        "Ranking uses dense ranks and forgets the positions occupied by ties.", """
        def competition_ranks(scores):
            output = []
            rank = 0
            previous = None
            for score in scores:
                if score != previous:
                    rank += 1
                output.append(rank)
                previous = score
            return output
        """, [_f([[100, 100, 90]], [1, 1, 3]), _f([[9, 8, 8, 7]], [1, 2, 2, 4]),
              _p([[9, 8, 7]], [1, 2, 3]), _p([[]], [])])

    cat = "aggregation-statistics"
    add(cat, "weighted-mean", "weighted_mean(values, weights)",
        "For equal-length numeric lists with positive total weight, return weighted sum divided by total weight.",
        "The weighted mean divides by the number of observations.", """
        def weighted_mean(values, weights):
            return sum(value * weight for value, weight in zip(values, weights)) / len(values)
        """, [_f([[2, 10], [1, 3]], 8.0), _f([[5], [4]], 5.0),
              _p([[2, 10], [1, 1]], 6.0), _p([[3], [1]], 3.0)])
    add(cat, "even-median", "median(values)",
        "Return the middle value for odd input, or average the two middle values for even input; empty input raises ValueError.",
        "The median returns the upper middle value for even-sized collections.", """
        def median(values):
            if not values:
                raise ValueError('nonempty input required')
            ordered = sorted(values)
            return ordered[len(ordered) // 2]
        """, [_f([[1, 9]], 5.0), _f([[4, 1, 3, 2]], 2.5), _p([[3, 1, 2]], 2), _p([[]], raises="ValueError")])
    add(cat, "rolling-window-sum", "rolling_sums(values, width)",
        "Return sums of every complete consecutive window for width>=1; width larger than input produces [].",
        "The rolling accumulator adds arrivals without subtracting departures.", """
        def rolling_sums(values, width):
            if len(values) < width:
                return []
            total = sum(values[:width])
            result = [total]
            for index in range(width, len(values)):
                total += values[index]
                result.append(total)
            return result
        """, [_f([[1, 2, 3, 4], 2], [3, 5, 7]), _f([[5, 0, 2], 1], [5, 0, 2]),
              _p([[1, 2], 2], [3]), _p([[1], 2], [])])
    add(cat, "missing-versus-zero", "mean_present(values)",
        "Average numeric values excluding only None; return None when no numeric values remain.",
        "Missing-value filtering also removes valid zero measurements.", """
        def mean_present(values):
            present = [value for value in values if value]
            return sum(present) / len(present) if present else None
        """, [_f([[0, 4, None]], 2.0), _f([[0, 0]], 0.0), _p([[2, None, 4]], 3.0), _p([[None]], None)])
    add(cat, "per-group-distinct", "distinct_counts(pairs)",
        "For [string-group,string-value] pairs, count distinct values independently within each group.",
        "Distinct counting incorrectly shares a single seen set between groups.", """
        def distinct_counts(pairs):
            seen = set()
            counts = {}
            for group, value in pairs:
                counts[group] = counts.get(group, 0)
                if value not in seen:
                    seen.add(value)
                    counts[group] += 1
            return counts
        """, [_f([[["a", "x"], ["b", "x"]]], {"a": 1, "b": 1}),
              _f([[["a", "x"], ["b", "x"], ["b", "y"]]], {"a": 1, "b": 2}),
              _p([[["a", "x"], ["a", "x"], ["a", "y"]]], {"a": 2}), _p([[]], {})])

    cat = "data-conversion"
    add(cat, "ragged-transpose", "transpose_rows(rows)",
        "Transpose ragged row lists through the longest row; fill absent positions with None; empty input returns [].",
        "Transposition truncates all rows to the shortest length.", """
        def transpose_rows(rows):
            return [list(column) for column in zip(*rows)]
        """, [_f([[[1, 2], [3]]], [[1, 3], [2, None]]), _f([[[], [1]]], [[None, 1]]),
              _p([[[1, 2], [3, 4]]], [[1, 3], [2, 4]]), _p([[]], [])])
    add(cat, "single-level-flatten", "flatten_once(values)",
        "Flatten list elements by exactly one level; retain nested lists below that level and scalar elements unchanged.",
        "Flattening wraps each child list as one item instead of expanding it.", """
        def flatten_once(values):
            result = []
            for value in values:
                result.append(value)
            return result
        """, [_f([[1, [2, 3], 4]], [1, 2, 3, 4]), _f([[[[1], 2], []]], [[1], 2]),
              _p([[1, 2]], [1, 2]), _p([[]], [])])
    add(cat, "little-endian-integer", "decode_le(octets)",
        "Decode a list of 0..255 octets as an unsigned little-endian integer; empty input returns 0.",
        "Byte decoding interprets the first octet as the most significant.", """
        def decode_le(octets):
            value = 0
            for octet in octets:
                value = value * 256 + octet
            return value
        """, [_f([[1, 2]], 513), _f([[2, 1, 0]], 258), _p([[7]], 7), _p([[]], 0)])
    add(cat, "zero-digit", "decimal_digits(number)",
        "For a nonnegative integer, return its decimal digits as integer list, including [0] for zero.",
        "The digit conversion loop produces no digit for zero.", """
        def decimal_digits(number):
            result = []
            while number > 0:
                result.append(number % 10)
                number //= 10
            return result[::-1]
        """, [_f([0], [0]), _p([507], [5, 0, 7]), _p([8], [8])])
    add(cat, "first-key-separator", "parse_assignment(text)",
        "Split at the first '=' into [trimmed key, trimmed value]; preserve later '=' in the value; missing separator raises ValueError.",
        "Assignment parsing attempts to unpack every separator in a value.", """
        def parse_assignment(text):
            key, value = text.split('=')
            return [key.strip(), value.strip()]
        """, [_f(["token = a=b=c"], ["token", "a=b=c"]), _f(["x=="], ["x", "="]),
              _p(["name = value"], ["name", "value"]), _p(["missing"], raises="ValueError")])

    cat = "state-transformations"
    add(cat, "falsy-overlay", "overlay(base, updates)",
        "Return a new dictionary with every update applied, including False, 0, '', and None; do not mutate base.",
        "Overlay application drops intentionally supplied falsy values.", """
        def overlay(base, updates):
            result = dict(base)
            for key, value in updates.items():
                if value:
                    result[key] = value
            return result
        """, [_f([{"enabled": True, "count": 8}, {"enabled": False, "count": 0}], {"enabled": False, "count": 0}),
              _f([{"name": "old"}, {"name": ""}], {"name": ""}), _p([{"x": 1}, {"x": 2}], {"x": 2}), _p([{"x": 1}, {}], {"x": 1})])
    add(cat, "nested-copy-isolation", "rename_profile(state, name)",
        "Input has {'profile': {'name': string}}. Return {'original': state, 'updated': renamed independent copy}; leave the original profile unchanged.",
        "A shallow update changes the original nested profile as well.", """
        def rename_profile(state, name):
            updated = dict(state)
            updated['profile']['name'] = name
            return {'original': state, 'updated': updated}
        """, [_f([{"profile": {"name": "Ada"}}, "Lin"], {"original": {"profile": {"name": "Ada"}}, "updated": {"profile": {"name": "Lin"}}}),
              _f([{"profile": {"name": "A", "age": 2}}, "B"], {"original": {"profile": {"name": "A", "age": 2}}, "updated": {"profile": {"name": "B", "age": 2}}}),
              _p([{"profile": {"name": "Ada"}}, "Ada"], {"original": {"profile": {"name": "Ada"}}, "updated": {"profile": {"name": "Ada"}}})])
    add(cat, "stack-pop-order", "stack_outputs(actions)",
        "Process ['push',value] or ['pop'] actions; return popped values in order; popping an empty stack raises ValueError.",
        "The stack implementation pops the oldest rather than newest value.", """
        def stack_outputs(actions):
            stack = []
            outputs = []
            for action in actions:
                if action[0] == 'push':
                    stack.append(action[1])
                else:
                    if not stack:
                        raise ValueError('empty stack')
                    outputs.append(stack.pop(0))
            return outputs
        """, [_f([[["push", 1], ["push", 2], ["pop"], ["pop"]]], [2, 1]),
              _f([[["push", "a"], ["push", "b"], ["pop"]]], ["b"]),
              _p([[["push", 7], ["pop"]]], [7]), _p([[["pop"]]], raises="ValueError")])
    add(cat, "operation-sequencing", "apply_operations(initial, operations)",
        "Apply ['add',n] and ['multiply',n] operations in listed order to an initial number.",
        "The transformation pipeline reverses the operation sequence.", """
        def apply_operations(initial, operations):
            value = initial
            for operation, operand in operations[::-1]:
                if operation == 'add':
                    value += operand
                else:
                    value *= operand
            return value
        """, [_f([2, [["add", 3], ["multiply", 4]]], 20), _f([3, [["multiply", 2], ["add", 5]]], 11),
              _p([2, [["add", 3]]], 5), _p([7, []], 7)])
    add(cat, "recent-access-order", "recent_keys(accesses, capacity)",
        "For capacity>=1, retain distinct accessed keys from least to most recent, refreshing existing keys and evicting the least recent when full.",
        "The cache treats repeat access as a no-op, causing FIFO rather than recent-access eviction.", """
        def recent_keys(accesses, capacity):
            keys = []
            for key in accesses:
                if key not in keys:
                    keys.append(key)
                if len(keys) > capacity:
                    keys.pop(0)
            return keys
        """, [_f([["a", "b", "a", "c"], 2], ["a", "c"]), _f([["a", "b", "a"], 3], ["b", "a"]),
              _p([["a", "b", "c"], 2], ["b", "c"]), _p([[], 1], [])])
    return tasks


def make_suite(seed: int = DEFAULT_SEED) -> list[dict[str, Any]]:
    """Create a fresh deterministic order of 50 distinct local repair fixtures."""
    if type(seed) is not int or not 0 <= seed <= 2**63 - 1:
        raise ValueError("suite seed must be a nonnegative integer below 2**63")
    tasks = _tasks()
    random.Random(seed).shuffle(tasks)
    return tasks


def public_task(task: dict[str, Any]) -> dict[str, Any]:
    """Explicit model-input projection; hidden evaluator cases are excluded."""
    return {field: task[field] for field in PUBLIC_FIELDS}
