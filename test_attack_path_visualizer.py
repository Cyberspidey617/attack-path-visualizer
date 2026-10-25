"""
test_attack_path_visualizer.py
==============================

Automated tests for the Cybersecurity Attack Path Visualizer (DAA Assignment 2).

Run from the project folder with either:
    python -m unittest -v
    python test_attack_path_visualizer.py

The algorithm tests need only the standard library. The GUI smoke tests at the
bottom create a hidden Tk window; they are skipped automatically if no display /
Tk is available.
"""

from __future__ import annotations

import itertools
import random
import unittest
from collections import deque

from traversal_core import (
    DEFAULT_SOURCE,
    DEFAULT_TARGET,
    MAX_DEVICES,
    GraphError,
    NetworkGraph,
    bfs,
    build_sample_network,
    dfs,
    is_valid_path,
    reconstruct_path,
    run_traversal,
)

ALGORITHMS = (bfs, dfs)


def reference_distance(graph: NetworkGraph, source: str, target: str) -> int | None:
    """Independent shortest-hop oracle (simple level-by-level expansion)."""
    if source == target:
        return 0
    frontier, seen, depth = {source}, {source}, 0
    while frontier:
        depth += 1
        nxt = set()
        for node in frontier:
            for nbr in graph.neighbors(node):
                if nbr == target:
                    return depth
                if nbr not in seen:
                    seen.add(nbr)
                    nxt.add(nbr)
        frontier = nxt
    return None


def reachable_set(graph: NetworkGraph, source: str) -> set[str]:
    seen, todo = {source}, deque([source])
    while todo:
        for nbr in graph.neighbors(todo.popleft()):
            if nbr not in seen:
                seen.add(nbr)
                todo.append(nbr)
    return seen


def line_graph(n: int) -> NetworkGraph:
    names = [f"N{i}" for i in range(n)]
    return NetworkGraph.from_spec(names, zip(names, names[1:]))


class PathAssertions(unittest.TestCase):
    def assertValidPath(self, graph, result):
        path = result.path
        self.assertTrue(result.found)
        self.assertEqual(path[0], result.source, "path must start at the source")
        self.assertEqual(path[-1], result.target, "path must end at the target")
        for a, b in zip(path, path[1:]):
            self.assertTrue(graph.has_connection(a, b), f"{a}-{b} is not an edge")
        self.assertEqual(len(path), len(set(path)), "path must not repeat vertices")
        self.assertTrue(is_valid_path(graph, path, result.source, result.target))
        self.assertEqual(result.hops, len(path) - 1)


# ----------------------------------------------------------------------------------
# 1-2. Normal graph and multiple paths
# ----------------------------------------------------------------------------------


class TestNormalGraph(PathAssertions):
    def setUp(self):
        self.graph, self.layout = build_sample_network()

    def test_01_reachable_target_bfs_and_dfs(self):
        for algo in ALGORITHMS:
            with self.subTest(algorithm=algo.__name__):
                result = algo(self.graph, DEFAULT_SOURCE, DEFAULT_TARGET)
                self.assertValidPath(self.graph, result)

    def test_02_multiple_paths_bfs_shortest_dfs_longer(self):
        b = bfs(self.graph, DEFAULT_SOURCE, DEFAULT_TARGET)
        d = dfs(self.graph, DEFAULT_SOURCE, DEFAULT_TARGET)
        self.assertEqual(b.path, ["Laptop-HR", "Switch-A", "Router-Core", "Firewall-Int", "DB-Server"])
        self.assertEqual(b.hops, 4)
        self.assertEqual(d.path, ["Laptop-HR", "Switch-A", "WS-Dev", "Switch-B", "Router-Core",
                                  "Firewall-Int", "DB-Server"])
        self.assertEqual(d.hops, 6)
        self.assertGreater(d.hops, b.hops, "sample network should show DFS is not always shortest")

    def test_sample_network_is_consistent(self):
        self.graph.validate()
        self.assertGreaterEqual(self.graph.device_count, 8)
        self.assertEqual(set(self.layout), set(self.graph.devices()))
        for x, y in self.layout.values():
            self.assertTrue(0 <= x <= 1 and 0 <= y <= 1)

    def test_bfs_traversal_order_is_by_layers(self):
        result = bfs(self.graph, DEFAULT_SOURCE, DEFAULT_TARGET, record_steps=False)
        distances = [reference_distance(self.graph, DEFAULT_SOURCE, v) for v in result.traversal_order]
        self.assertEqual(distances, sorted(distances), "BFS must dequeue in non-decreasing distance")


# ----------------------------------------------------------------------------------
# 3-8. Boundary and invalid cases
# ----------------------------------------------------------------------------------


class TestBoundaryCases(PathAssertions):
    def test_03_source_equals_target(self):
        graph, _ = build_sample_network()
        for algo in ALGORITHMS:
            with self.subTest(algorithm=algo.__name__):
                result = algo(graph, "Switch-A", "Switch-A")
                self.assertTrue(result.found)
                self.assertEqual(result.path, ["Switch-A"])
                self.assertEqual(result.hops, 0)
                self.assertEqual(result.path_vertex_count, 1)
                self.assertEqual(result.steps[-1].action, "found")

    def test_04_unreachable_target(self):
        graph, _ = build_sample_network()  # Legacy-Kiosk is isolated
        for algo in ALGORITHMS:
            with self.subTest(algorithm=algo.__name__):
                result = algo(graph, DEFAULT_SOURCE, "Legacy-Kiosk")
                self.assertFalse(result.found)
                self.assertEqual(result.path, [])
                self.assertIsNone(result.hops)
                self.assertEqual(result.steps[-1].action, "not_found")
                self.assertIn("No path", result.steps[-1].explanation)
                # it must have explored the whole component before giving up
                self.assertEqual(set(result.visited), reachable_set(graph, DEFAULT_SOURCE))

    def test_05_disconnected_graph(self):
        graph = NetworkGraph.from_spec(["A", "B", "C", "X", "Y", "Z"],
                                       [("A", "B"), ("B", "C"), ("X", "Y"), ("Y", "Z")])
        for algo in ALGORITHMS:
            with self.subTest(algorithm=algo.__name__):
                self.assertFalse(algo(graph, "A", "Z").found)
                self.assertEqual(set(algo(graph, "A", "Z").visited), {"A", "B", "C"})
                self.assertValidPath(graph, algo(graph, "X", "Z"))

    def test_06_single_node_graph(self):
        graph = NetworkGraph.from_spec(["Solo"])
        for algo in ALGORITHMS:
            with self.subTest(algorithm=algo.__name__):
                result = algo(graph, "Solo", "Solo")
                self.assertEqual(result.path, ["Solo"])
                self.assertEqual(result.visited_count, 1)

    def test_07_cyclic_graph_terminates(self):
        # complete graph K6 has many cycles; a ring of 50 has one long cycle
        k6 = NetworkGraph.from_spec("ABCDEF", itertools.combinations("ABCDEF", 2))
        ring = NetworkGraph.from_spec([f"R{i}" for i in range(30)],
                                      [(f"R{i}", f"R{(i + 1) % 30}") for i in range(30)])
        for graph, s, t, expected in ((k6, "A", "F", 1), (ring, "R0", "R15", 15), (ring, "R0", "R29", 1)):
            for algo in ALGORITHMS:
                with self.subTest(graph=graph.device_count, algorithm=algo.__name__, target=t):
                    result = algo(graph, s, t)  # would hang/raise if cycles were mishandled
                    self.assertValidPath(graph, result)
                    self.assertEqual(len(result.visited), len(set(result.visited)))
                    if algo is bfs:
                        self.assertEqual(result.hops, expected)

    def test_07b_cycle_with_unreachable_target_terminates(self):
        graph = NetworkGraph.from_spec(["A", "B", "C", "Island"], [("A", "B"), ("B", "C"), ("C", "A")])
        for algo in ALGORITHMS:
            with self.subTest(algorithm=algo.__name__):
                result = algo(graph, "A", "Island")
                self.assertFalse(result.found)
                self.assertEqual(result.edge_checks, 2 * graph.connection_count)

    def test_08_invalid_source_or_target(self):
        graph, _ = build_sample_network()
        bad_inputs = [("Nope", DEFAULT_TARGET), (DEFAULT_SOURCE, "Nope"), ("", DEFAULT_TARGET),
                      (DEFAULT_SOURCE, ""), (None, DEFAULT_TARGET), (DEFAULT_SOURCE, 42),
                      ("laptop-hr", DEFAULT_TARGET)]  # names are case-sensitive references
        for algo in ALGORITHMS:
            for s, t in bad_inputs:
                with self.subTest(algorithm=algo.__name__, source=s, target=t):
                    with self.assertRaises(GraphError):
                        algo(graph, s, t)

    def test_08b_invalid_algorithm_name(self):
        graph, _ = build_sample_network()
        with self.assertRaises(GraphError):
            run_traversal(graph, "Dijkstra", DEFAULT_SOURCE, DEFAULT_TARGET)
        self.assertEqual(run_traversal(graph, " bfs ", DEFAULT_SOURCE, DEFAULT_TARGET).algorithm, "BFS")

    def test_11_empty_graph(self):
        graph = NetworkGraph()
        self.assertEqual(graph.device_count, 0)
        self.assertEqual(graph.connections(), [])
        for algo in ALGORITHMS:
            with self.subTest(algorithm=algo.__name__):
                with self.assertRaisesRegex(GraphError, "empty"):
                    algo(graph, "A", "B")


# ----------------------------------------------------------------------------------
# 9-10. Algorithm correctness against an oracle on many random graphs
# ----------------------------------------------------------------------------------


class TestAlgorithmCorrectness(PathAssertions):
    def random_graph(self, rng: random.Random, n: int, p: float) -> NetworkGraph:
        names = [f"D{i}" for i in range(n)]
        graph = NetworkGraph.from_spec(names)
        for a, b in itertools.combinations(names, 2):
            if rng.random() < p:
                graph.add_connection(a, b)
        return graph

    def test_09_bfs_returns_minimum_hops_on_random_graphs(self):
        rng = random.Random(2026)
        for trial in range(300):
            graph = self.random_graph(rng, rng.randint(1, 18), rng.choice((0.08, 0.15, 0.3, 0.6)))
            nodes = graph.devices()
            s, t = rng.choice(nodes), rng.choice(nodes)
            with self.subTest(trial=trial):
                expected = reference_distance(graph, s, t)
                result = bfs(graph, s, t, record_steps=False)
                if expected is None:
                    self.assertFalse(result.found)
                else:
                    self.assertValidPath(graph, result)
                    self.assertEqual(result.hops, expected)

    def test_10_dfs_reachability_and_path_validity_on_random_graphs(self):
        rng = random.Random(7)
        for trial in range(300):
            graph = self.random_graph(rng, rng.randint(1, 18), rng.choice((0.08, 0.15, 0.3, 0.6)))
            nodes = graph.devices()
            s, t = rng.choice(nodes), rng.choice(nodes)
            with self.subTest(trial=trial):
                result = dfs(graph, s, t, record_steps=False)
                self.assertEqual(result.found, t in reachable_set(graph, s))
                if result.found:
                    self.assertValidPath(graph, result)
                    self.assertGreaterEqual(result.hops, reference_distance(graph, s, t))

    def test_each_vertex_visited_at_most_once_and_edge_checks_bounded(self):
        rng = random.Random(99)
        for trial in range(100):
            graph = self.random_graph(rng, rng.randint(2, 20), 0.3)
            s = graph.devices()[0]
            # Add an isolated target so each run is exhaustive (explores the whole component).
            island_graph = graph.copy()
            island_graph.add_device("Island")
            for algo in ALGORITHMS:
                with self.subTest(trial=trial, algorithm=algo.__name__):
                    result = algo(island_graph, s, "Island", record_steps=False)
                    self.assertEqual(len(result.visited), len(set(result.visited)))
                    # O(V + E) evidence: every adjacency entry is examined at most once
                    reach = reachable_set(island_graph, s)
                    expected_checks = sum(len(island_graph.neighbors(v)) for v in reach)
                    self.assertEqual(result.edge_checks, expected_checks)
                    self.assertLessEqual(result.edge_checks, 2 * island_graph.connection_count)

    def test_reconstruct_path(self):
        parent = {"A": None, "B": "A", "C": "B"}
        self.assertEqual(reconstruct_path(parent, "A", "C"), ["A", "B", "C"])
        self.assertEqual(reconstruct_path(parent, "A", "Z"), [])

    def test_record_steps_does_not_change_result(self):
        graph, _ = build_sample_network()
        for algo in ALGORITHMS:
            with_steps = algo(graph, DEFAULT_SOURCE, DEFAULT_TARGET, record_steps=True)
            without = algo(graph, DEFAULT_SOURCE, DEFAULT_TARGET, record_steps=False)
            self.assertEqual(with_steps.path, without.path)
            self.assertEqual(with_steps.traversal_order, without.traversal_order)
            self.assertEqual(without.steps, [])

    def test_deep_line_graph_has_no_recursion_problem(self):
        graph = line_graph(MAX_DEVICES)
        for algo in ALGORITHMS:
            result = algo(graph, "N0", f"N{MAX_DEVICES - 1}")
            self.assertEqual(result.hops, MAX_DEVICES - 1)


# ----------------------------------------------------------------------------------
# Step recording used by the GUI
# ----------------------------------------------------------------------------------


class TestStepRecording(unittest.TestCase):
    def setUp(self):
        self.graph, _ = build_sample_network()

    def test_steps_are_indexed_and_bracketed(self):
        for algo in ALGORITHMS:
            steps = algo(self.graph, DEFAULT_SOURCE, DEFAULT_TARGET).steps
            self.assertEqual([s.index for s in steps], list(range(len(steps))))
            self.assertEqual(steps[0].action, "init")
            self.assertEqual(steps[-1].action, "found")
            self.assertTrue(all(s.explanation for s in steps))
            self.assertTrue(all(not s.path for s in steps[:-1]), "path is revealed only at the end")

    def test_bfs_queue_is_fifo(self):
        steps = bfs(self.graph, DEFAULT_SOURCE, DEFAULT_TARGET).steps
        for before, after in zip(steps, steps[1:]):
            if after.action == "dequeue":
                self.assertEqual(after.current, before.frontier[0])
                self.assertEqual(after.frontier, before.frontier[1:])
            if after.action == "discover":
                self.assertEqual(after.frontier[-1], after.examined_edge[1])

    def test_dfs_stack_is_current_branch(self):
        steps = dfs(self.graph, DEFAULT_SOURCE, DEFAULT_TARGET).steps
        for step in steps:
            stack = list(step.frontier)
            for a, b in zip(stack, stack[1:]):
                self.assertTrue(self.graph.has_connection(a, b), "stack must be a path")
        self.assertEqual(list(steps[-1].frontier), list(steps[-1].path))

    def test_visited_grows_monotonically(self):
        for algo in ALGORITHMS:
            steps = algo(self.graph, DEFAULT_SOURCE, "Legacy-Kiosk").steps
            for before, after in zip(steps, steps[1:]):
                self.assertEqual(after.visited[:len(before.visited)], before.visited)

    def test_steps_are_immutable(self):
        step = bfs(self.graph, DEFAULT_SOURCE, DEFAULT_TARGET).steps[0]
        with self.assertRaises(Exception):
            step.current = "hacked"  # type: ignore[misc]


# ----------------------------------------------------------------------------------
# 12. Graph editor validation
# ----------------------------------------------------------------------------------


class TestGraphEditing(unittest.TestCase):
    def setUp(self):
        self.graph = NetworkGraph.from_spec([("A", "Router"), ("B", "Server"), "C"], [("A", "B")])

    def test_12a_duplicate_edge_rejected_both_directions(self):
        with self.assertRaises(GraphError):
            self.graph.add_connection("A", "B")
        with self.assertRaises(GraphError):
            self.graph.add_connection("B", "A")
        self.assertEqual(self.graph.connection_count, 1)

    def test_12b_self_loop_rejected(self):
        with self.assertRaises(GraphError):
            self.graph.add_connection("A", "A")

    def test_12c_edge_to_unknown_device_rejected(self):
        for a, b in (("A", "Ghost"), ("Ghost", "A"), (None, "A")):
            with self.subTest(a=a, b=b), self.assertRaises(GraphError):
                self.graph.add_connection(a, b)

    def test_12d_device_name_validation(self):
        for bad in ("", "   ", "x" * 21, "-dash-first", "bad/name", "semi;colon", None, 5):
            with self.subTest(name=bad), self.assertRaises(GraphError):
                self.graph.add_device(bad)
        with self.assertRaises(GraphError):
            self.graph.add_device("a")  # case-insensitive duplicate of "A"
        with self.assertRaises(GraphError):
            self.graph.add_device("Valid", "Toaster")
        self.assertEqual(self.graph.add_device("  Web Server 2  ", "Server"), "Web Server 2")

    def test_12e_device_limit(self):
        graph = NetworkGraph()
        for i in range(MAX_DEVICES):
            graph.add_device(f"D{i}")
        with self.assertRaises(GraphError):
            graph.add_device("OneTooMany")

    def test_undirected_symmetry(self):
        self.graph.add_connection("C", "A")
        self.assertTrue(self.graph.has_connection("A", "C"))
        self.assertTrue(self.graph.has_connection("C", "A"))
        self.graph.validate()

    def test_remove_connection(self):
        self.graph.remove_connection("B", "A")
        self.assertFalse(self.graph.has_connection("A", "B"))
        with self.assertRaises(GraphError):
            self.graph.remove_connection("A", "B")
        self.graph.validate()

    def test_remove_device_removes_its_edges(self):
        self.graph.add_connection("C", "B")
        self.graph.remove_device("B")
        self.assertNotIn("B", self.graph)
        self.assertEqual(self.graph.connection_count, 0)
        self.assertEqual(self.graph.neighbors("A"), ())
        self.graph.validate()
        with self.assertRaises(GraphError):
            self.graph.remove_device("B")

    def test_neighbors_returns_copy(self):
        nbrs = self.graph.neighbors("A")
        self.assertIsInstance(nbrs, tuple)
        self.assertEqual(self.graph.neighbors("A"), ("B",))

    def test_copy_is_independent(self):
        clone = self.graph.copy()
        clone.add_connection("A", "C")
        self.assertFalse(self.graph.has_connection("A", "C"))

    def test_validate_detects_corruption(self):
        self.graph._adjacency["A"].append("C")  # one-sided edge (white-box test)
        with self.assertRaises(GraphError):
            self.graph.validate()


# ----------------------------------------------------------------------------------
# GUI smoke tests (skipped automatically when no display is available)
# ----------------------------------------------------------------------------------

try:
    import tkinter as tk

    _probe = tk.Tk()
    _probe.destroy()
    TK_AVAILABLE = True
except Exception:  # noqa: BLE001 - any failure means "no usable display"
    TK_AVAILABLE = False


@unittest.skipUnless(TK_AVAILABLE, "Tkinter display not available")
class TestGuiSmoke(unittest.TestCase):
    def setUp(self):
        from attack_path_visualizer import AttackPathVisualizerApp

        self.root = tk.Tk()
        self.root.withdraw()
        self.app = AttackPathVisualizerApp(self.root)
        self.errors: list[str] = []
        self.app.error_handler = self.errors.append
        self.root.update()

    def tearDown(self):
        self.app._stop_autoplay()
        self.root.destroy()

    def test_startup_defaults(self):
        self.assertEqual(self.app.source_var.get(), DEFAULT_SOURCE)
        self.assertEqual(self.app.target_var.get(), DEFAULT_TARGET)
        self.assertIn(DEFAULT_SOURCE, self.app.source_combo.cget("values"))
        self.assertIsNone(self.app.result)

    def test_generate_navigate_and_reset(self):
        self.assertTrue(self.app.generate_steps())
        total = len(self.app.result.steps)
        self.assertEqual(self.app.step_index, 0)
        self.app.next_step()
        self.app.next_step()
        self.assertEqual(self.app.step_index, 2)
        self.app.previous_step()
        self.assertEqual(self.app.step_index, 1)
        self.app.run_to_completion()
        self.assertEqual(self.app.step_index, total - 1)
        self.app.next_step()  # must not go past the end
        self.assertEqual(self.app.step_index, total - 1)
        self.assertIn("YES", self.app.outcome_var.get())
        self.assertEqual(self.app.hops_var.get().split()[0], "4")
        self.root.update()  # the log-selection event must not loop forever
        self.app.reset_traversal()
        self.assertIsNone(self.app.result)
        self.assertEqual(self.app.step_var.get(), "0 / 0")

    def test_dfs_and_no_path_in_gui(self):
        self.app.algorithm_var.set("DFS")
        self.app.run_to_completion()
        self.assertEqual(self.app.hops_var.get().split()[0], "6")
        self.app.target_var.set("Legacy-Kiosk")  # changing selection resets
        self.assertIsNone(self.app.result)
        self.app.run_to_completion()
        self.assertIn("NO", self.app.outcome_var.get())

    def test_missing_selection_reports_error(self):
        self.app.target_var.set("")
        self.assertFalse(self.app.generate_steps())
        self.assertTrue(self.errors and "target" in self.errors[-1].lower())

    def test_editor_actions(self):
        self.app.new_name_var.set("IoT-Camera")
        self.app.add_device()
        self.assertIn("IoT-Camera", self.app.graph)
        self.assertIn("IoT-Camera", self.app.layout)
        self.app.edge_a_var.set("IoT-Camera")
        self.app.edge_b_var.set("DB-Server")
        self.app.add_connection()
        self.app.add_connection()  # duplicate
        self.assertEqual(len(self.errors), 1)
        self.app.edge_a_var.set("IoT-Camera")
        self.app.edge_b_var.set("IoT-Camera")
        self.app.add_connection()  # self-loop
        self.assertEqual(len(self.errors), 2)
        self.app.remove_var.set("IoT-Camera")
        self.app.remove_device()
        self.assertNotIn("IoT-Camera", self.app.graph)
        self.app.clear_network(confirm=False)
        self.assertEqual(self.app.graph.device_count, 0)
        self.assertFalse(self.app.generate_steps())
        self.app.load_sample_network()
        self.assertTrue(self.app.generate_steps())

    def test_compare(self):
        self.app.compare_algorithms()
        text = self.app.compare_var.get()
        self.assertIn("BFS: 4 hop", text)
        self.assertIn("DFS: 6 hop", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
