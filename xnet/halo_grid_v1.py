"""Inert HALO 6×6 planning data, independent of every live runtime.

Cell labels and the sum 111 are arithmetic properties of the supplied layout,
not measured costs, physical node identities, security, inference or learning.
No callback, process, network, sensor, scope or scheduler is owned or activated.
"""
from __future__ import annotations

SCHEMA = "xnet.halo-grid-plan.v1"
GRID = ((6, 32, 3, 34, 35, 1), (7, 11, 27, 28, 8, 30),
        (19, 14, 16, 15, 23, 24), (18, 20, 22, 21, 17, 13),
        (25, 29, 10, 9, 26, 12), (36, 5, 33, 4, 2, 31))
SIZE = 6
MAX_ROUNDS = 16


def validate_grid(grid=GRID):
    if (type(grid) not in (list, tuple) or len(grid) != SIZE
            or any(type(row) not in (list, tuple) or len(row) != SIZE for row in grid)):
        raise ValueError("HALO requires exactly six rows of six cells")
    cells = [cell for row in grid for cell in row]
    if any(type(cell) is not int for cell in cells) or sorted(cells) != list(range(1, 37)):
        raise ValueError("HALO requires each exact integer 1 through 36 once")
    rows = [sum(row) for row in grid]
    columns = [sum(grid[row][column] for row in range(SIZE)) for column in range(SIZE)]
    diagonals = [sum(grid[index][index] for index in range(SIZE)),
                 sum(grid[index][SIZE - 1 - index] for index in range(SIZE))]
    if rows != [111] * SIZE or columns != [111] * SIZE or diagonals != [111, 111] or sum(cells) != 666:
        raise ValueError("HALO row, column, diagonal or total arithmetic differs")
    if tuple(tuple(row) for row in grid) != GRID:
        raise ValueError("HALO requires the exact supplied layout, not another square")
    return {"rows": rows, "columns": columns, "diagonals": diagonals, "total": sum(cells),
            "unique_cells": len(set(cells)), "numeric_sums_are_costs": False}


def slot_id(row, column):
    if any(type(value) is not int or not 1 <= value <= SIZE for value in (row, column)):
        raise ValueError("HALO slot coordinates must be exact integers 1 through 6")
    return f"halo-r{row:02d}-c{column:02d}"


def slot(identifier):
    if type(identifier) is not str:
        raise ValueError("exact HALO slot ID required")
    for row in range(1, SIZE + 1):
        for column in range(1, SIZE + 1):
            if identifier == slot_id(row, column):
                return {"slot_id": identifier, "row": row, "column": column,
                        "cell_label": GRID[row - 1][column - 1], "lane_id": f"halo-row-{row:02d}",
                        "physical_node": None}
    raise ValueError("unknown or noncanonical HALO slot ID")


def plan(*, rounds=1, grid=GRID):
    arithmetic = validate_grid(grid)
    if type(rounds) is not int or not 1 <= rounds <= MAX_ROUNDS:
        raise ValueError("HALO requires a bounded exact round count 1 through 16")
    slots = [slot(slot_id(row, column)) for row in range(1, 7) for column in range(1, 7)]
    phases = []
    for cycle in range(1, rounds + 1):
        for phase in range(SIZE):
            visits = [slot(slot_id(row + 1, (row + phase) % SIZE + 1)) for row in range(SIZE)]
            phases.append({"phase_id": f"halo-round-{cycle:03d}-phase-{phase + 1:02d}",
                           "round": cycle, "phase": phase + 1, "visits": visits})
    return {"schema": SCHEMA, "name": "HALO 6×6", "classification": "future-topology-planning-only",
            "source": "user supplied numeric layout; original image bytes are not pinned",
            "grid": [list(row) for row in GRID], "arithmetic": arithmetic,
            "rounds": rounds, "lanes": [f"halo-row-{row:02d}" for row in range(1, 7)],
            "slots": slots, "phases": phases, "visits_per_slot": rounds,
            "routing_rule": "zero-based column=(row+phase) mod 6; one visit per row and column per phase",
            "balance_basis": "visit counts only; heterogeneous durations and costs remain unknown",
            "authority": "none", "scheduler_activated": False, "physical_nodes_attested": False,
            "process_calls": 0, "network_calls": 0, "sensor_calls": 0, "model_calls": 0,
            "weights_updated": False, "performance_improvement_measured": False}
