"""Fresh, controlled multi-file Python repairs; these are not official SWE-bench.

The fixture author never supplies repaired source. Only ``public_task`` belongs
in worker context. Held-out cases and their expectation rationales are local
grader data. Seed changes ordering, never the problems or their tests.
"""
from __future__ import annotations

import copy
import random
import textwrap

DEFAULT_SEED = 20261005
FIXTURE_VERSION = "xnet.swe-repair-fixtures.v1"
PUBLIC_FIELDS = ("task_id", "category", "issue", "files", "entry_file",
                 "entry_function", "editable_files", "api_contract", "public_cases")


def _case(kind, args, expected=None, *, kwargs=None, raises=None):
    case = {"case_type": kind, "args": args, "kwargs": kwargs or {}}
    case["raises" if raises else "expected"] = raises if raises else expected
    return case


def _f(args, expected=None, **options):
    return _case("F2P", args, expected, **options)


def _p(args, expected=None, **options):
    return _case("P2P", args, expected, **options)


def _source(text):
    return textwrap.dedent(text).strip() + "\n"


def _tasks():
    tasks = []

    def add(category, slug, signature, requirements, issue, helpers, api, cases, extra=None):
        task_id = "swe50--" + category + "--" + slug
        function = signature.split("(", 1)[0]
        files = {"helpers.py": _source(helpers), "api.py": _source(api)}
        if extra:
            files.update({path: _source(source) for path, source in extra.items()})
        named = [{**case, "name": function, "case_id": task_id + "-" + str(index),
                  "hidden": index > 2}
                 for index, case in enumerate(cases, 1)]
        tasks.append({"task_id": task_id, "category": category, "issue": issue,
                      "files": files, "entry_file": "api.py", "entry_function": function,
                      "editable_files": list(files), "fixture_version": FIXTURE_VERSION,
                      "api_contract": {"signature": signature, "requirements": requirements,
                                       "dependencies": "Only the supplied local modules and Python builtins.",
                                       "replacement_limit_bytes": 8192},
                      "public_cases": named[:2], "hidden_cases": named[2:],
                      "case_rationale": "F2P exercises the reported policy; P2P preserves supported behavior."})

    cat = "billing-policy"
    add(cat, "metered-tiers", "invoice_usage(units, limit, base_rate, excess_rate, fixed_cents=0)",
        "Nonnegative integer units/cents. Units through limit cost base_rate each; remaining units cost excess_rate each. Add fixed_cents once.",
        "Invoices for customers crossing the usage tier disagree with the published tier pricing.", """
        def usage_charge(units, limit, base_rate, excess_rate):
            return min(units, limit) * base_rate + max(0, units - limit) * base_rate
        """, """
        from helpers import usage_charge
        def invoice_usage(units, limit, base_rate, excess_rate, fixed_cents=0):
            return fixed_cents + usage_charge(units, limit, base_rate, excess_rate)
        """, [_f([12, 10, 5, 2], 54), _p([4, 10, 5, 2], 20),
              _f([15, 5, 4, 1], 37, kwargs={"fixed_cents": 7}),
              _f([9, 2, 1, 3], 23), _p([0, 10, 5, 2], 9, kwargs={"fixed_cents": 9}),
              _p([10, 10, 5, 2], 50)])
    add(cat, "coupon-threshold", "checkout_total(lines, minimum_cents, coupon_cents)",
        "lines are [quantity, unit_cents]. Apply coupon when subtotal is at least minimum_cents, then clamp total to zero.",
        "Checkout rejects valid coupons on orders that exactly meet the advertised minimum.", """
        def coupon_eligible(subtotal, minimum):
            return subtotal > minimum
        def line_subtotal(lines):
            return sum(quantity * price for quantity, price in lines)
        """, """
        from helpers import coupon_eligible, line_subtotal
        def checkout_total(lines, minimum_cents, coupon_cents):
            subtotal = line_subtotal(lines)
            return max(0, subtotal - coupon_cents) if coupon_eligible(subtotal, minimum_cents) else subtotal
        """, [_f([[[2, 50]], 100, 20], 80), _p([[[3, 50]], 100, 20], 130),
              _f([[[1, 25], [3, 25]], 100, 15], 85), _f([[[1, 40]], 40, 60], 0),
              _p([[[1, 50]], 100, 20], 50), _p([[], 10, 3], 0)])
    add(cat, "per-line-tax", "tax_total(line_cents, basis_points)",
        "Return tax cents only. Tax each line separately at basis_points/10000 and round half up to integer cents, then add the line taxes.",
        "The tax report understates lines whose fractional tax should round up.", """
        def rounded_tax(cents, basis_points):
            return cents * basis_points // 10000
        """, """
        from helpers import rounded_tax
        def tax_total(line_cents, basis_points):
            return sum(rounded_tax(cents, basis_points) for cents in line_cents)
        """, [_f([[110, 110], 500], 12), _p([[100, 200], 500], 15),
              _f([[199], 1000], 20), _f([[50, 150], 100], 3),
              _p([[], 750], 0), _p([[101], 500], 5)])
    add(cat, "available-credit", "approve_credit(line_cents, prior_credits, requested_cents)",
        "Return min(requested_cents, max(0, sum(line_cents)-sum(prior_credits))). Inputs are nonnegative cents.",
        "A second credit request can exceed the remaining refundable invoice balance.", """
        def cap_credit(requested, balance):
            return min(requested, max(0, balance))
        def remaining_balance(lines, credits):
            return sum(lines) - sum(credits)
        """, """
        from helpers import cap_credit, remaining_balance
        def approve_credit(line_cents, prior_credits, requested_cents):
            balance = remaining_balance(line_cents, [])
            return cap_credit(requested_cents, balance)
        """, [_f([[100], [40], 80], 60), _p([[100], [], 80], 80),
              _f([[30, 20], [60], 10], 0), _f([[80, 40], [30, 20], 100], 70),
              _p([[100], [20], 10], 10), _p([[], [], 10], 0)])
    add(cat, "service-proration", "service_charge(monthly_cents, active_days, month_days)",
        "For positive month_days and 0<=active_days<=month_days, prorate monthly_cents by days and round the final fractional cent half up.",
        "Partial-month service charges lose the rounding required by the billing contract.", """
        def prorated_cents(monthly, days, period):
            return monthly * days // period
        """, """
        from helpers import prorated_cents
        def service_charge(monthly_cents, active_days, month_days):
            return prorated_cents(monthly_cents, active_days, month_days)
        """, [_f([101, 15, 30], 51), _p([100, 15, 30], 50),
              _f([99, 2, 4], 50), _f([7, 2, 3], 5), _p([120, 30, 30], 120), _p([120, 0, 30], 0)])

    cat = "inventory-planning"
    add(cat, "live-reservations", "available_stock(on_hand, reservations, now)",
        "reservations are [quantity, expires_at] integer ticks. Only reservations with expires_at>now consume stock. Return max(0,on_hand-live quantities).",
        "Availability includes reservations that expire exactly at the query time.", """
        def reserved_now(reservations, now):
            return sum(quantity for quantity, expires in reservations if expires >= now)
        """, """
        from helpers import reserved_now
        def available_stock(on_hand, reservations, now):
            return max(0, on_hand - reserved_now(reservations, now))
        """, [_f([10, [[4, 5]], 5], 10), _p([10, [[4, 6]], 5], 6),
              _f([12, [[3, 7], [4, 8]], 7], 8), _f([5, [[9, 2]], 2], 5),
              _p([8, [[3, 1]], 2], 8), _p([3, [[5, 9]], 2], 0)])
    add(cat, "bundle-bottleneck", "buildable_bundles(stock, recipe)",
        "stock and recipe map part names to nonnegative stock and positive required units. Return the minimum stock[name]//recipe[name], missing parts count zero; empty recipe returns zero.",
        "Bundle availability overstates production when a recipe needs more than one unit of a part.", """
        def part_capacity(stock, part, required):
            return stock.get(part, 0)
        """, """
        from helpers import part_capacity
        def buildable_bundles(stock, recipe):
            return min([part_capacity(stock, part, required) for part, required in recipe.items()]) if recipe else 0
        """, [_f([{"a": 8, "b": 5}, {"a": 2, "b": 1}], 4), _p([{"a": 8}, {"a": 1}], 8),
              _f([{"a": 3, "b": 9}, {"a": 2, "b": 3}], 1), _f([{"x": 10}, {"x": 3}], 3),
              _p([{}, {"missing": 2}], 0), _p([{"a": 1}, {}], 0)])
    add(cat, "returned-units", "closing_stock(opening, movements)",
        "movements are [kind,quantity], kind receipt/sale/return. Receipts and customer returns increase stock; sales decrease it. Return the final integer stock.",
        "Daily stock reconciliation reduces inventory for customer returns.", """
        def movement_delta(kind, quantity):
            return quantity if kind == 'receipt' else -quantity
        """, """
        from helpers import movement_delta
        def closing_stock(opening, movements):
            return opening + sum(movement_delta(kind, quantity) for kind, quantity in movements)
        """, [_f([10, [["sale", 3], ["return", 2]]], 9), _p([10, [["sale", 3]]], 7),
              _f([0, [["return", 4], ["receipt", 1]]], 5), _f([8, [["return", 2], ["return", 1]]], 11),
              _p([3, [["receipt", 7], ["sale", 2]]], 8), _p([5, []], 5)])
    add(cat, "reorder-deficit", "reorder_quantity(on_hand, inbound, target, pack_size)",
        "Positive pack_size. Count inbound stock toward target. Order the least whole number of packs covering max(0,target-on_hand-inbound); return units ordered.",
        "Reorder suggestions purchase stock already covered by inbound shipments.", """
        def order_packs(deficit, size):
            return ((max(0, deficit) + size - 1) // size) * size
        """, """
        from helpers import order_packs
        def reorder_quantity(on_hand, inbound, target, pack_size):
            return order_packs(target - on_hand, pack_size)
        """, [_f([3, 5, 10, 4], 4), _p([3, 0, 10, 4], 8),
              _f([2, 9, 10, 5], 0), _f([0, 3, 8, 2], 6),
              _p([12, 0, 10, 3], 0), _p([10, 1, 10, 4], 0)])
    add(cat, "lot-pick-plan", "pick_lots(lots, requested)",
        "lots are [lot_id,quantity] in oldest-first order. Return [id,picked] rows, skipping zero picks, consuming oldest stock until requested is met or stock is exhausted.",
        "Pick plans consume the newest lot before the oldest lot.", """
        def allocation(lot, remaining):
            return min(lot[1], remaining)
        """, """
        from helpers import allocation
        def pick_lots(lots, requested):
            result = []
            remaining = requested
            for lot in reversed(lots):
                taken = allocation(lot, remaining)
                if taken:
                    result.append([lot[0], taken])
                    remaining -= taken
            return result
        """, [_f([[["old", 3], ["new", 4]], 5], [["old", 3], ["new", 2]]),
              _p([[["only", 4]], 3], [["only", 3]]),
              _f([[["a", 1], ["b", 2], ["c", 3]], 2], [["a", 1], ["b", 1]]),
              _f([[["a", 2], ["b", 1]], 9], [["a", 2], ["b", 1]]),
              _p([[], 2], []), _p([[["a", 2], ["b", 1]], 0], [])])

    cat = "scheduling-rules"
    add(cat, "resource-conflicts", "conflicting_bookings(bookings, resource, start, end)",
        "bookings are [id,resource,start,end], with half-open integer intervals. Return IDs in input order only when resource matches and intervals overlap.",
        "A room search reports conflicts from reservations assigned to other rooms.", """
        def intervals_overlap(left_start, left_end, right_start, right_end):
            return left_start < right_end and right_start < left_end
        """, """
        from helpers import intervals_overlap
        def conflicting_bookings(bookings, resource, start, end):
            return [identifier for identifier, room, begin, finish in bookings if intervals_overlap(begin, finish, start, end)]
        """, [_f([[["a", "blue", 2, 6], ["b", "red", 3, 7]], "blue", 4, 5], ["a"]),
              _p([[["a", "blue", 2, 6]], "blue", 4, 5], ["a"]),
              _f([[["a", "red", 0, 4]], "blue", 1, 2], []),
              _f([[["a", "x", 1, 5], ["b", "y", 2, 4], ["c", "x", 2, 3]], "x", 2, 4], ["a", "c"]),
              _p([[["a", "blue", 0, 2]], "blue", 2, 5], []), _p([[], "blue", 0, 5], [])])
    add(cat, "cooldown-start", "schedule_after(previous_end, cooldown, requested_start)",
        "Integer ticks and nonnegative cooldown. Return the earliest permitted start at or after requested_start and at least cooldown ticks after previous_end.",
        "The scheduler places successive jobs inside their required cleanup period.", """
        def ready_at(previous_end, cooldown):
            return previous_end
        """, """
        from helpers import ready_at
        def schedule_after(previous_end, cooldown, requested_start):
            return max(ready_at(previous_end, cooldown), requested_start)
        """, [_f([10, 3, 11], 13), _p([10, 3, 15], 15),
              _f([5, 4, 0], 9), _f([7, 2, 7], 9), _p([8, 0, 4], 8), _p([0, 2, 2], 2)])
    add(cat, "capacity-ticks", "overloaded_ticks(bookings, horizon, capacity)",
        "bookings are [start,end,units] and occupy start<=tick<end. Return ticks in range(horizon) whose total units exceed capacity.",
        "Capacity warnings persist into the tick when a booking has already ended.", """
        def tick_load(bookings, tick):
            return sum(units for start, end, units in bookings if start <= tick <= end)
        """, """
        from helpers import tick_load
        def overloaded_ticks(bookings, horizon, capacity):
            return [tick for tick in range(horizon) if tick_load(bookings, tick) > capacity]
        """, [_f([[[0, 2, 1], [2, 4, 1]], 4, 1], []),
              _p([[[0, 4, 2]], 4, 1], [0, 1, 2, 3]),
              _f([[[1, 2, 3]], 4, 2], [1]), _f([[[0, 1, 2], [1, 3, 2]], 3, 3], []),
              _p([[], 4, 0], []), _p([[[0, 3, 1]], 3, 1], [])])
    add(cat, "whole-window-fit", "valid_starts(candidates, duration, windows)",
        "Nonnegative integer duration; windows are [start,end]. Preserve candidates whose entire [candidate,candidate+duration] fits within one window, including exact endpoint fit.",
        "Available start suggestions include appointments that run past a window's closing time.", """
        def fits_window(start, duration, window):
            return window[0] <= start <= window[1]
        """, """
        from helpers import fits_window
        def valid_starts(candidates, duration, windows):
            return [start for start in candidates if any(fits_window(start, duration, window) for window in windows)]
        """, [_f([[2, 4], 3, [[1, 5]]], [2]), _p([[1, 2], 3, [[1, 5]]], [1, 2]),
              _f([[5], 1, [[0, 5]]], []), _f([[3, 8], 3, [[0, 4], [7, 10]]], []),
              _p([[0, 5], 0, [[0, 5]]], [0, 5]), _p([[2], 2, []], [])])
    add(cat, "recurrence-anchor", "next_occurrence(now, anchor, period)",
        "Positive integer period. Events occur at anchor+k*period for integer k>=0. Return the first occurrence at or after now.",
        "Recurring events drift from their configured anchor when the anchor is not a period multiple.", """
        def recurrence_tick(now, anchor, period):
            if now <= anchor:
                return anchor
            return now + (period - now % period) % period
        """, """
        from helpers import recurrence_tick
        def next_occurrence(now, anchor, period):
            return recurrence_tick(now, anchor, period)
        """, [_f([8, 3, 5], 8), _p([8, 0, 5], 10),
              _f([10, 2, 4], 10), _f([7, 1, 3], 7), _p([1, 5, 3], 5), _p([6, 0, 3], 6)])

    cat = "catalog-selection"
    add(cat, "language-fallback", "catalog_labels(records, locale, default_locale)",
        "records are [id,{locale:text}]. Select exact locale, else language before first '-', else default_locale, else ''. Empty supplied text is valid. Return id-to-text map.",
        "Regional locales fail to use an available language translation before falling back to the default.", """
        def translated_label(labels, locale, default_locale):
            return labels.get(locale, labels.get(default_locale, ''))
        """, """
        from helpers import translated_label
        def catalog_labels(records, locale, default_locale):
            return {identifier: translated_label(labels, locale, default_locale) for identifier, labels in records}
        """, [_f([[["a", {"en": "Tea", "fr": "The"}]], "en-US", "fr"], {"a": "Tea"}),
              _p([[["a", {"en-US": "Tea", "fr": "The"}]], "en-US", "fr"], {"a": "Tea"}),
              _f([[["x", {"pt": "Cha"}]], "pt-BR", "en"], {"x": "Cha"}),
              _f([[["x", {"en": "", "fr": "The"}]], "en-GB", "fr"], {"x": ""}),
              _p([[["x", {"fr": "The"}]], "de-DE", "fr"], {"x": "The"}), _p([[], "en", "fr"], {})])
    add(cat, "purchasable-size", "available_variants(variants, wanted_size)",
        "variants are [id,size,stock]. Sizes compare after stripping and casefolding. Return IDs in input order only when size matches and stock is strictly positive.",
        "The size selector offers sold-out variants as purchasable.", """
        def same_size(left, right):
            return left.strip().casefold() == right.strip().casefold()
        """, """
        from helpers import same_size
        def available_variants(variants, wanted_size):
            return [identifier for identifier, size, stock in variants if same_size(size, wanted_size) and stock >= 0]
        """, [_f([[["a", "M", 0], ["b", "m", 2]], "M"], ["b"]),
              _p([[["a", " M ", 2], ["b", "L", 3]], "m"], ["a"]),
              _f([[["x", "xs", 0]], " XS "], []), _f([[["a", "L", 0], ["b", "L", 0]], "l"], []),
              _p([[["a", "M", -1]], "m"], []), _p([[], "m"], [])])
    add(cat, "exclusive-price-band", "price_band_labels(price_cents, bands)",
        "bands are [label,lower,upper] integer cents. Return all labels with lower<=price_cents<upper, preserving input order.",
        "A price on the boundary appears in both adjacent catalog bands.", """
        def band_contains(price, lower, upper):
            return lower <= price <= upper
        """, """
        from helpers import band_contains
        def price_band_labels(price_cents, bands):
            return [label for label, lower, upper in bands if band_contains(price_cents, lower, upper)]
        """, [_f([100, [["low", 0, 100], ["high", 100, 200]]], ["high"]),
              _p([50, [["low", 0, 100], ["high", 100, 200]]], ["low"]),
              _f([200, [["high", 100, 200]]], []), _f([0, [["empty", 0, 0], ["normal", 0, 1]]], ["normal"]),
              _p([100, [["high", 100, 200]]], ["high"]), _p([-1, [["normal", 0, 100]]], [])])
    add(cat, "all-query-terms", "matching_products(products, query)",
        "products are [id,title]. Split query and title on whitespace and casefold tokens. Every query token must occur as a full title token. Empty query matches all products. Preserve ID order.",
        "Catalog search returns titles containing only one part of a multiword query.", """
        def title_matches(title, terms):
            words = title.casefold().split()
            return any(term in words for term in terms) if terms else True
        """, """
        from helpers import title_matches
        def matching_products(products, query):
            terms = query.casefold().split()
            return [identifier for identifier, title in products if title_matches(title, terms)]
        """, [_f([[["a", "Blue Tea"], ["b", "Blue Cup"]], "blue tea"], ["a"]),
              _p([[["a", "Blue Tea"], ["b", "Red Tea"]], "blue"], ["a"]),
              _f([[["a", "Green Bowl"], ["b", "Tea Mug"]], "green tea"], []),
              _f([[["a", "Tea"], ["b", "Hot Tea"]], "hot TEA"], ["b"]),
              _p([[["a", "Teapot"]], "tea"], []), _p([[["a", "Tea"], ["b", "Cup"]], ""], ["a", "b"])])
    add(cat, "alias-chain", "canonical_names(names, aliases)",
        "Follow aliases repeatedly until a name has no alias. Return canonical names in input order. Any alias cycle reached from an input raises ValueError.",
        "Catalog canonicalization stops early when an alias points to another alias.", """
        def canonical_name(name, aliases):
            return aliases.get(name, name)
        """, """
        from helpers import canonical_name
        def canonical_names(names, aliases):
            return [canonical_name(name, aliases) for name in names]
        """, [_f([["a"], {"a": "b", "b": "c"}], ["c"]),
              _p([["a", "x"], {"a": "b"}], ["b", "x"]),
              _f([["a"], {"a": "b", "b": "a"}], raises="ValueError"),
              _f([["x", "a"], {"a": "b", "b": "c", "c": "d"}], ["x", "d"]),
              _p([[], {"a": "a"}], []), _p([["unknown"], {}], ["unknown"])])

    cat = "ledger-reconciliation"
    add(cat, "posted-only", "account_balances(rows)",
        "rows are [account,signed_cents,state]. Include only state=='posted'; pending and void rows have no effect. Return balances for accounts having posted rows, including zero balances.",
        "Account reports recognize pending transactions before they have been posted.", """
        def recognized(state):
            return state != 'void'
        """, """
        from helpers import recognized
        def account_balances(rows):
            balances = {}
            for account, cents, state in rows:
                if recognized(state):
                    balances[account] = balances.get(account, 0) + cents
            return balances
        """, [_f([[["a", 100, "posted"], ["a", 50, "pending"]]], {"a": 100}),
              _p([[["a", 100, "posted"], ["a", -20, "void"]]], {"a": 100}),
              _f([[["a", 12, "pending"]]], {}),
              _f([[["a", 20, "posted"], ["b", 2, "pending"], ["a", -20, "posted"]]], {"a": 0}),
              _p([[],], {}), _p([[["a", 5, "posted"], ["b", -3, "posted"]]], {"a": 5, "b": -3})])
    add(cat, "reversal-references", "unreversed_total(entries, reversed_ids)",
        "entries are [unique_id,signed_cents]. Reversal IDs identify entire original entries to exclude, irrespective of amount. Unknown reversal IDs are ignored. Return remaining sum.",
        "The reconciled total still includes original entries that have been reversed by ID.", """
        def retained_entries(entries, reversed_ids):
            return entries
        """, """
        from helpers import retained_entries
        def unreversed_total(entries, reversed_ids):
            return sum(cents for identifier, cents in retained_entries(entries, reversed_ids))
        """, [_f([[["a", 100], ["b", 100]], ["a"]], 100),
              _p([[["a", 100], ["b", -20]], []], 80),
              _f([[["a", -40], ["b", 20]], ["a"]], 20),
              _f([[["a", 10], ["b", 15]], ["a", "b", "unknown"]], 0),
              _p([[["a", 30]], ["missing"]], 30), _p([[], ["a"]], 0)])
    add(cat, "unique-batch-ids", "validated_batch_total(rows)",
        "rows are [transaction_id,signed_cents]. Transaction IDs must be unique within the batch, including equal-value duplicates. Raise ValueError for duplicates; otherwise return sum.",
        "Batch import silently accepts repeated transaction IDs and double-counts their amounts.", """
        def validate_identifiers(rows):
            return True
        """, """
        from helpers import validate_identifiers
        def validated_batch_total(rows):
            validate_identifiers(rows)
            return sum(cents for identifier, cents in rows)
        """, [_f([[["a", 10], ["a", 10]]], raises="ValueError"),
              _p([[["a", 10], ["b", 10]]], 20),
              _f([[["a", 10], ["b", 5], ["a", -10]]], raises="ValueError"),
              _f([[["x", 0], ["x", 0]]], raises="ValueError"),
              _p([[],], 0), _p([[["a", -5], ["b", 5]]], 0)])
    add(cat, "signed-cash-rounding", "cash_adjustment(cents, denomination)",
        "Positive even denomination in cents. Round signed cents to its nearest multiple, with exact halves away from zero; return rounded minus original cents.",
        "Cash adjustments for negative half-denomination amounts use the wrong tie direction.", """
        def rounded_cash(cents, denomination):
            return ((cents + denomination // 2) // denomination) * denomination
        """, """
        from helpers import rounded_cash
        def cash_adjustment(cents, denomination):
            return rounded_cash(cents, denomination) - cents
        """, [_f([-25, 10], -5), _p([25, 10], 5),
              _f([-15, 10], -5), _f([-6, 4], -2), _p([-24, 10], 4), _p([0, 10], 0)])
    add(cat, "deposit-fee-policy", "settlement_total(transactions, deposit_fee)",
        "transactions are signed cents. Subtract deposit_fee once from each strictly positive transaction. Zero transactions and negative refunds have no deposit fee. Return sum of settled cents.",
        "Settlement subtracts a deposit fee from refunds and zero-value adjustments.", """
        def settled_amount(cents, fee):
            return cents - fee
        """, """
        from helpers import settled_amount
        def settlement_total(transactions, deposit_fee):
            return sum(settled_amount(cents, deposit_fee) for cents in transactions)
        """, [_f([[100, -30], 5], 65), _p([[100, 30], 5], 120),
              _f([[0], 7], 0), _f([[-20, -10, 40], 2], 8),
              _p([[], 5], 0), _p([[0, -3, 10], 0], 7)])

    cat = "event-analytics"
    add(cat, "ordered-funnel", "completed_funnels(events)",
        "events are [user,stage] in event order. Return sorted unique users having a 'view' followed later by a 'buy'. Earlier buys do not count unless another buy follows a view.",
        "Funnel analytics attribute conversions to users whose only purchase preceded their first view.", """
        def converted_users(events):
            viewers = {user for user, stage in events if stage == 'view'}
            return sorted({user for user, stage in events if stage == 'buy' and user in viewers})
        """, """
        from helpers import converted_users
        def completed_funnels(events):
            return converted_users(events)
        """, [_f([[["a", "buy"], ["a", "view"]]], []),
              _p([[["a", "view"], ["a", "buy"]]], ["a"]),
              _f([[["b", "buy"], ["a", "view"], ["a", "buy"], ["b", "view"]]], ["a"]),
              _f([[["a", "buy"], ["a", "view"], ["b", "view"], ["b", "buy"]]], ["b"]),
              _p([[["a", "buy"], ["a", "view"], ["a", "buy"]]], ["a"]), _p([[],], [])])
    add(cat, "terminal-histogram", "histogram(values, edges)",
        "edges has at least two strictly increasing numbers. Count values into [edge[i],edge[i+1]) bins, except the final bin also includes its right endpoint. Ignore out-of-range values.",
        "The final histogram bin drops observations equal to the highest configured edge.", """
        def bin_index(value, edges):
            for index in range(len(edges) - 1):
                if edges[index] <= value < edges[index + 1]:
                    return index
            return -1
        """, """
        from helpers import bin_index
        def histogram(values, edges):
            counts = [0 for index in range(len(edges) - 1)]
            for value in values:
                index = bin_index(value, edges)
                if index >= 0:
                    counts[index] += 1
            return counts
        """, [_f([[0, 10, 20], [0, 10, 20]], [1, 2]),
              _p([[1, 11], [0, 10, 20]], [1, 1]),
              _f([[5, 5, 6], [0, 5]], [2]), _f([[-2, 0, 2], [-2, 0, 2]], [1, 2]),
              _p([[-1, 21], [0, 10, 20]], [0, 0]), _p([[], [0, 1]], [0])])
    add(cat, "idle-session-boundary", "session_lengths(timestamps, max_gap)",
        "timestamps are sorted integer ticks; max_gap>=0. Start a new session only when the next gap is strictly greater than max_gap. Return event counts per session; empty input returns [].",
        "Session reports split activity whose idle gap is exactly the allowed timeout.", """
        def starts_session(previous, current, max_gap):
            return current - previous >= max_gap
        """, """
        from helpers import starts_session
        def session_lengths(timestamps, max_gap):
            if not timestamps:
                return []
            counts = [1]
            for previous, current in zip(timestamps, timestamps[1:]):
                if starts_session(previous, current, max_gap):
                    counts.append(1)
                else:
                    counts[-1] += 1
            return counts
        """, [_f([[0, 5, 10], 5], [3]), _p([[0, 2, 10], 5], [2, 1]),
              _f([[1, 1, 2], 0], [2, 1]), _f([[0, 2, 4, 9], 2], [3, 1]),
              _p([[], 3], []), _p([[7], 0], [1])])
    add(cat, "nearest-rank-percentile", "percentile(values, percent)",
        "values is nonempty; percent is an integer 1..100. Sort values and return the nearest-rank percentile at one-based rank ceil(percent*len(values)/100).",
        "Percentiles landing on an exact rank select the following observation.", """
        def percentile_index(count, percent):
            return min(count - 1, count * percent // 100)
        """, """
        from helpers import percentile_index
        def percentile(values, percent):
            ordered = sorted(values)
            return ordered[percentile_index(len(ordered), percent)]
        """, [_f([[4, 1, 3, 2], 50], 2), _p([[3, 1, 2], 25], 1),
              _f([[10, 20, 30, 40, 50], 20], 10), _f([[1, 2, 3, 4], 75], 3),
              _p([[10, 20, 30], 100], 30), _p([[7], 50], 7)])
    add(cat, "streak-after-gap", "longest_active_streak(days)",
        "days are integer day indices in any order. Ignore duplicates. Return the longest count of consecutive active days, or zero for an empty list.",
        "An activity streak beginning after an inactive gap is undercounted.", """
        def streak_length(ordered_days):
            if not ordered_days:
                return 0
            current = 1
            best = 1
            for previous, day in zip(ordered_days, ordered_days[1:]):
                current = current + 1 if day == previous + 1 else 0
                best = max(best, current)
            return best
        """, """
        from helpers import streak_length
        def longest_active_streak(days):
            return streak_length(sorted(set(days)))
        """, [_f([[1, 5, 6, 7]], 3), _p([[3, 1, 2, 2]], 3),
              _f([[2, 10, 11]], 2), _f([[1, 2, 7, 8, 9, 10]], 4),
              _p([[],], 0), _p([[1, 5]], 1)])

    cat = "structured-records"
    add(cat, "quoted-tab-fields", "parse_tab_row(line)",
        "Parse one valid TSV row. A field may be enclosed in double quotes; inside quotes tabs are literal and doubled quotes decode to one quote. Preserve empty fields. No embedded newlines.",
        "Tab-separated imports split quoted fields containing a literal tab.", """
        from quoting import unquote_field
        def tab_fields(line):
            return [unquote_field(field) for field in line.split('\t')]
        """, """
        from helpers import tab_fields
        def parse_tab_row(line):
            return tab_fields(line)
        """, [_f(['"a\tb"\tc'], ["a\tb", "c"]), _p(['"ab"\tc'], ["ab", "c"]),
              _f(['x\t"y\tz"\t'], ["x", "y\tz", ""]),
              _f(['"a\tb"\t"c\td"'], ["a\tb", "c\td"]),
              _p(['"a""b"\tc'], ['a"b', "c"]), _p(['a\t\t'], ["a", "", ""])],
        extra={"quoting.py": """
        def unquote_field(field):
            if field.startswith('"') and field.endswith('"'):
                return field[1:-1].replace('""', '"')
            return field
        """})
    add(cat, "missing-nested-path", "read_paths(record, paths, default=None)",
        "paths are lists of dictionary keys. Traverse nested dictionaries. Missing keys or a non-dict intermediate return default. Empty path returns record. Existing values, including None, are returned as-is.",
        "Optional nested fields raise lookup errors instead of producing the caller's default.", """
        def nested_value(record, path, default):
            current = record
            for key in path:
                current = current[key]
            return current
        """, """
        from helpers import nested_value
        def read_paths(record, paths, default=None):
            return [nested_value(record, path, default) for path in paths]
        """, [_f([{"a": {"b": 2}}, [["a", "missing"]]], [9], kwargs={"default": 9}),
              _p([{"a": {"b": 2}}, [["a", "b"]]], [2]),
              _f([{"a": 3}, [["a", "b"]]], ["absent"], kwargs={"default": "absent"}),
              _f([{}, [["missing"], []]], [None, {}]),
              _p([{"a": None, "b": False}, [["a"], ["b"]]], [None, False]),
              _p([{"a": 2}, [[]]], [{"a": 2}])])
    add(cat, "localized-minor-units", "amount_in_cents(text, locale)",
        "Valid en-US strings use ',' grouping and '.' decimal; valid de-DE strings use '.' grouping and ',' decimal. Decimal fraction has exactly two digits. Optional leading '-' applies to whole amount. Return integer cents.",
        "The record importer interprets German money strings using US separators.", """
        from money_parts import minor_units
        def localized_amount(text, locale):
            return minor_units(text.replace(',', '').split('.'))
        """, """
        from helpers import localized_amount
        def amount_in_cents(text, locale):
            return localized_amount(text, locale)
        """, [_f(["1.234,56", "de-DE"], 123456), _p(["1,234.56", "en-US"], 123456),
              _f(["-12,50", "de-DE"], -1250), _f(["0,09", "de-DE"], 9),
              _p(["-0.09", "en-US"], -9), _p(["0.00", "en-US"], 0)],
        extra={"money_parts.py": """
        def minor_units(parts):
            sign = -1 if parts[0].startswith('-') else 1
            return sign * (abs(int(parts[0])) * 100 + int(parts[1]))
        """})
    add(cat, "escaped-pipe-row", "encode_pipe_row(values)",
        "values are strings. Escape every original backslash as two backslashes and every original '|' as backslash+'|'. Join escaped fields with unescaped '|'. Preserve empty fields.",
        "Exported rows over-escape pipe characters and cannot be read by the downstream parser.", r"""
        def escape_field(value):
            return value.replace('|', '\\|').replace('\\', '\\\\')
        """, """
        from helpers import escape_field
        def encode_pipe_row(values):
            return '|'.join(escape_field(value) for value in values)
        """, [_f([["a|b", "c"]], "a\\|b|c"), _p([["a", "b"]], "a|b"),
              _f([["|", ""]], "\\||"), _f([["a\\|b"]], "a\\\\\\|b"),
              _p([["a\\b", ""]], "a\\\\b|"), _p([[]], "")])
    add(cat, "zero-length-run", "decode_runs(runs)",
        "runs are [string,count] with integer count. Concatenate repeated symbols into a list. Zero-count runs contribute nothing; any negative count raises ValueError.",
        "The run decoder emits a phantom symbol for empty runs and accepts invalid negative counts.", """
        def expand_run(symbol, count):
            return [symbol] * max(1, count)
        """, """
        from helpers import expand_run
        def decode_runs(runs):
            decoded = []
            for symbol, count in runs:
                decoded.extend(expand_run(symbol, count))
            return decoded
        """, [_f([[["a", 0], ["b", 2]]], ["b", "b"]),
              _p([[["a", 2], ["b", 1]]], ["a", "a", "b"]),
              _f([[["x", -1]]], raises="ValueError"), _f([[["a", 0], ["b", 0]]], []),
              _p([[],], []), _p([[["", 2]]], ["", ""])])

    cat = "order-fulfillment"
    add(cat, "rotatable-package", "cheapest_box(item_dimensions, boxes)",
        "Three positive dimensions per item/box. boxes are [id,dimensions,cost_cents]. Item can rotate, so sorted dimensions must fit pairwise. Return cheapest fitting box ID, first in input order on ties; None if none fit.",
        "Box selection rejects packages that would fit after rotating the item.", """
        def package_fits(item, box):
            return all(needed <= available for needed, available in zip(item, box))
        """, """
        from helpers import package_fits
        def cheapest_box(item_dimensions, boxes):
            chosen = None
            cost = None
            for identifier, dimensions, cents in boxes:
                if package_fits(item_dimensions, dimensions) and (cost is None or cents < cost):
                    chosen = identifier
                    cost = cents
            return chosen
        """, [_f([[4, 2, 3], [["a", [2, 3, 4], 10]]], "a"),
              _p([[2, 3, 4], [["a", [2, 3, 4], 10]]], "a"),
              _f([[3, 5, 2], [["a", [2, 3, 5], 5], ["b", [6, 6, 6], 20]]], "a"),
              _f([[3, 1, 2], [["a", [1, 2, 3], 8], ["b", [3, 3, 3], 8]]], "a"),
              _p([[4, 4, 4], [["a", [3, 4, 5], 10]]], None), _p([[1, 2, 3], []], None)])
    add(cat, "full-weight-batch", "shipment_groups(weights, capacity)",
        "Positive weights each <=positive capacity. Greedily append weights in input order to the current group while total<=capacity; otherwise start the next group. Return groups; empty input returns [].",
        "Shipment batching starts a new parcel when the current parcel would be filled exactly.", """
        def can_append(group, weight, capacity):
            return sum(group) + weight < capacity
        """, """
        from helpers import can_append
        def shipment_groups(weights, capacity):
            groups = []
            for weight in weights:
                if groups and can_append(groups[-1], weight, capacity):
                    groups[-1].append(weight)
                else:
                    groups.append([weight])
            return groups
        """, [_f([[2, 3, 1], 5], [[2, 3], [1]]), _p([[2, 2, 3], 5], [[2, 2], [3]]),
              _f([[1, 1, 1], 3], [[1, 1, 1]]), _f([[3, 2, 5], 5], [[3, 2], [5]]),
              _p([[], 5], []), _p([[5], 5], [[5]])])
    add(cat, "all-or-nothing-line", "fulfill_lines(orders, stock, allow_partial=False)",
        "orders are [sku,quantity]. Process in order against copied stock, missing SKU=0. If partial delivery is disabled, an insufficient line receives zero; otherwise receive min(available,quantity). Return [sku,filled,backordered] per line.",
        "Fulfillment partially ships order lines whose contract requires complete quantities.", """
        from policies import partial_quantity
        def allocation_quantity(available, requested, allow_partial):
            return partial_quantity(available, requested)
        """, """
        from helpers import allocation_quantity
        def fulfill_lines(orders, stock, allow_partial=False):
            available = stock.copy()
            result = []
            for sku, quantity in orders:
                filled = allocation_quantity(available.get(sku, 0), quantity, allow_partial)
                available[sku] = available.get(sku, 0) - filled
                result.append([sku, filled, quantity - filled])
            return result
        """, [_f([[["a", 5]], {"a": 3}], [["a", 0, 5]]),
              _p([[["a", 5]], {"a": 3}], [["a", 3, 2]], kwargs={"allow_partial": True}),
              _f([[["a", 4], ["a", 2]], {"a": 3}], [["a", 0, 4], ["a", 2, 0]]),
              _f([[["a", 2], ["a", 2]], {"a": 3}], [["a", 2, 0], ["a", 0, 2]]),
              _p([[["a", 2], ["a", 1]], {"a": 3}], [["a", 2, 0], ["a", 1, 0]]),
              _p([[["missing", 2]], {}], [["missing", 0, 2]])],
        extra={"policies.py": """
        def partial_quantity(available, requested):
            return min(available, requested)
        """})
    add(cat, "skip-oversized-stop", "dispatch_ids(orders, capacity)",
        "orders are [id,positive_weight]. Walk input order, accept an order when it fits remaining capacity, otherwise skip it and continue. Return accepted IDs.",
        "Dispatch planning stops after a heavy order and misses later orders that still fit.", """
        def within_capacity(loaded, weight, capacity):
            return loaded + weight <= capacity
        """, """
        from helpers import within_capacity
        def dispatch_ids(orders, capacity):
            result = []
            loaded = 0
            for identifier, weight in orders:
                if not within_capacity(loaded, weight, capacity):
                    break
                result.append(identifier)
                loaded += weight
            return result
        """, [_f([[["heavy", 8], ["light", 3]], 5], ["light"]),
              _p([[["a", 2], ["b", 3]], 5], ["a", "b"]),
              _f([[["a", 3], ["b", 4], ["c", 2]], 5], ["a", "c"]),
              _f([[["a", 6], ["b", 7], ["c", 1]], 2], ["c"]),
              _p([[["a", 6]], 5], []), _p([[], 5], [])])
    add(cat, "dispatch-cutoff", "delivery_day(placed_day, placed_tick, cutoff_tick, transit_days, service_weekdays)",
        "Integer days, day0 weekday0 modulo7; nonnegative transit_days. Orders placed strictly before cutoff dispatch that day, otherwise next day. Add transit_days, then advance to the first weekday in the nonempty service_weekdays list.",
        "Delivery promises dispatch an order placed exactly at cutoff one day too early.", """
        def dispatch_day(day, tick, cutoff):
            return day if tick <= cutoff else day + 1
        def next_service_day(day, weekdays):
            while day % 7 not in weekdays:
                day += 1
            return day
        """, """
        from helpers import dispatch_day, next_service_day
        def delivery_day(placed_day, placed_tick, cutoff_tick, transit_days, service_weekdays):
            ready = dispatch_day(placed_day, placed_tick, cutoff_tick) + transit_days
            return next_service_day(ready, service_weekdays)
        """, [_f([0, 10, 10, 2, [0, 1, 2, 3, 4, 5, 6]], 3),
              _p([0, 9, 10, 2, [0, 1, 2, 3, 4, 5, 6]], 2),
              _f([3, 10, 10, 1, [0, 1, 2, 3, 4]], 7),
              _f([6, 5, 5, 0, [0, 1, 2, 3, 4, 5, 6]], 7),
              _p([0, 11, 10, 2, [0, 1, 2, 3, 4, 5, 6]], 3),
              _p([4, 9, 10, 1, [0, 1, 2, 3, 4]], 7)])

    from xnet.swe_repair_additions import add_additions
    add_additions(add, _f, _p)
    return tasks


def build_swe_repair_suite(seed=DEFAULT_SEED):
    """Return fresh fixture objects in reproducible seed-shuffled order."""
    if type(seed) is not int or not 0 <= seed < 2 ** 63:
        raise ValueError("seed must be an integer in [0,2**63)")
    tasks = _tasks()
    if len(tasks) != 50 or len({task["task_id"] for task in tasks}) != 50:
        raise ValueError("suite must contain exactly fifty unique tasks")
    random.Random(seed).shuffle(tasks)
    return tasks


def public_task(task):
    """Copy only model-visible issue, module graph, API, and smoke tests."""
    return copy.deepcopy({field: task[field] for field in PUBLIC_FIELDS})


# Keep the familiar suite spelling available to local tooling.
make_suite = build_swe_repair_suite
