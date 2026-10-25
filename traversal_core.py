"""
traversal_core.py
=================

Algorithm layer for the *Cybersecurity Attack Path Visualizer* (DAA Assignment 2).

This module contains NO GUI code. It provides:

* ``NetworkGraph``   - an undirected, unweighted graph stored as an adjacency list.
* ``bfs``            - Breadth-First Search (finds a minimum-hop path).
* ``dfs``            - Depth-First Search (finds *a* path, not necessarily the shortest).
* ``TraversalStep``  - an immutable snapshot of the algorithm state, used by the GUI
                       for step-by-step playback.
* ``TraversalResult``- the final outcome of a traversal.
* ``build_sample_network`` - the default simulated enterprise network.

Everything here is an EDUCATIONAL SIMULATION. No real network is scanned,
contacted or attacked; the "devices" are just strings in a Python dictionary.

Complexity summary (V = number of vertices/devices, E = number of edges/connections)
-----------------------------------------------------------------------------------
* Graph storage (adjacency list) .................. O(V + E)
* BFS time ........................................ O(V + E)
* DFS time ........................................ O(V + E)
* BFS auxiliary space (queue, visited, parent) .... O(V)
* DFS auxiliary space (stack, visited, parent,
  neighbour iterators) ............................ O(V)

The *step history* recorded for the GUI is NOT part of the algorithm's auxiliary
space. Each snapshot copies the queue/stack, visited set, traversal order and
tree edges (O(V) each), and there are O(V + E) snapshots, so recording costs
O((V + E) * V) extra memory. Passing ``record_steps=False`` disables it and the
functions then use only the O(V) auxiliary space stated above.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from typing import Iterable, Iterator

# --------------------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------------------

DEVICE_TYPES: tuple[str, ...] = (
    "Workstation",
    "Switch",
    "Router",
    "Firewall",
    "Gateway",
    "Server",
)

#: Short labels drawn inside each node on the canvas.
TYPE_ABBREVIATIONS: dict[str, str] = {
    "Workstation": "WS",
    "Switch": "SW",
    "Router": "RT",
    "Firewall": "FW",
    "Gateway": "GW",
    "Server": "SV",
}

MAX_NAME_LENGTH = 20
MAX_DEVICES = 30  # keeps the canvas readable; documented limitation

# Letters/digits first, then letters, digits, space, underscore, dot or hyphen.
_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-]*$")

ALGORITHMS: tuple[str, ...] = ("BFS", "DFS")


class GraphError(ValueError):
    """Raised for any invalid graph operation or invalid traversal input."""


# --------------------------------------------------------------------------------------
# Graph representation
# --------------------------------------------------------------------------------------


class NetworkGraph:
    """Undirected, unweighted graph of simulated network devices.

    Internally ``_adjacency`` maps each device name to a list of neighbouring
    device names (an adjacency list). Every undirected connection {a, b} is
    stored twice: ``b`` in ``_adjacency[a]`` and ``a`` in ``_adjacency[b]``.
    Neighbour order is insertion order, which makes BFS/DFS output deterministic.

    Storage: O(V + E).
    """

    def __init__(self) -> None:
        self._adjacency: dict[str, list[str]] = {}
        self._device_type: dict[str, str] = {}

    # ---- construction helpers --------------------------------------------------

    @classmethod
    def from_spec(
        cls,
        devices: Iterable[str | tuple[str, str]],
        connections: Iterable[tuple[str, str]] = (),
    ) -> "NetworkGraph":
        """Build a graph from device names (or ``(name, type)`` pairs) and edges."""
        graph = cls()
        for item in devices:
            if isinstance(item, tuple):
                graph.add_device(item[0], item[1])
            else:
                graph.add_device(item)
        for a, b in connections:
            graph.add_connection(a, b)
        return graph

    def copy(self) -> "NetworkGraph":
        """Return an independent deep copy of the graph."""
        clone = NetworkGraph()
        clone._adjacency = {node: list(nbrs) for node, nbrs in self._adjacency.items()}
        clone._device_type = dict(self._device_type)
        return clone

    # ---- validation ------------------------------------------------------------

    @staticmethod
    def normalize_name(name: object) -> str:
        """Validate a device name and return it with surrounding spaces removed."""
        if not isinstance(name, str):
            raise GraphError("Device name must be text.")
        cleaned = name.strip()
        if not cleaned:
            raise GraphError("Device name cannot be empty.")
        if len(cleaned) > MAX_NAME_LENGTH:
            raise GraphError(f"Device name must be at most {MAX_NAME_LENGTH} characters.")
        if not _NAME_PATTERN.match(cleaned):
            raise GraphError(
                "Device name must start with a letter or digit and may contain only "
                "letters, digits, spaces, '_', '.' or '-'."
            )
        return cleaned

    def _require(self, name: object) -> str:
        if not isinstance(name, str) or name not in self._adjacency:
            raise GraphError(f"Unknown device: {name!r}.")
        return name

    def validate(self) -> None:
        """Check internal consistency (symmetry, no self-loops, no duplicates).

        Raises ``GraphError`` if the adjacency list is inconsistent.
        """
        for node, nbrs in self._adjacency.items():
            if len(nbrs) != len(set(nbrs)):
                raise GraphError(f"Duplicate connection stored for {node!r}.")
            for nbr in nbrs:
                if nbr == node:
                    raise GraphError(f"Self-connection on {node!r}.")
                if nbr not in self._adjacency:
                    raise GraphError(f"{node!r} references unknown device {nbr!r}.")
                if node not in self._adjacency[nbr]:
                    raise GraphError(f"Connection {node!r}-{nbr!r} is not symmetric.")

    # ---- mutation --------------------------------------------------------------

    def add_device(self, name: object, device_type: str = "Workstation") -> str:
        """Add an isolated device. Returns the cleaned name.  O(V) for the
        case-insensitive duplicate check (V <= 30, so this is negligible)."""
        cleaned = self.normalize_name(name)
        if device_type not in DEVICE_TYPES:
            raise GraphError(f"Unknown device type: {device_type!r}.")
        if len(self._adjacency) >= MAX_DEVICES:
            raise GraphError(f"The network is limited to {MAX_DEVICES} devices.")
        for existing in self._adjacency:
            if existing.lower() == cleaned.lower():
                raise GraphError(f"A device named '{existing}' already exists.")
        self._adjacency[cleaned] = []
        self._device_type[cleaned] = device_type
        return cleaned

    def remove_device(self, name: object) -> None:
        """Remove a device and every connection that touches it."""
        node = self._require(name)
        for nbr in self._adjacency[node]:
            self._adjacency[nbr].remove(node)
        del self._adjacency[node]
        del self._device_type[node]

    def add_connection(self, a: object, b: object) -> None:
        """Add the undirected edge {a, b}. Rejects self-loops and duplicates."""
        a = self._require(a)
        b = self._require(b)
        if a == b:
            raise GraphError("A device cannot be connected to itself.")
        if b in self._adjacency[a]:
            raise GraphError(f"'{a}' and '{b}' are already connected.")
        self._adjacency[a].append(b)
        self._adjacency[b].append(a)

    def remove_connection(self, a: object, b: object) -> None:
        """Remove the undirected edge {a, b}."""
        a = self._require(a)
        b = self._require(b)
        if b not in self._adjacency[a]:
            raise GraphError(f"'{a}' and '{b}' are not connected.")
        self._adjacency[a].remove(b)
        self._adjacency[b].remove(a)

    # ---- queries ---------------------------------------------------------------

    def has_device(self, name: object) -> bool:
        return isinstance(name, str) and name in self._adjacency

    def has_connection(self, a: object, b: object) -> bool:
        return self.has_device(a) and self.has_device(b) and b in self._adjacency[a]

    def neighbors(self, name: object) -> tuple[str, ...]:
        """Neighbours of ``name`` in insertion order (a copy, so callers cannot
        corrupt the graph)."""
        return tuple(self._adjacency[self._require(name)])

    def device_type(self, name: object) -> str:
        return self._device_type[self._require(name)]

    def devices(self) -> list[str]:
        return list(self._adjacency)

    def connections(self) -> list[tuple[str, str]]:
        """Each undirected edge exactly once, in a stable order."""
        seen: set[frozenset[str]] = set()
        result: list[tuple[str, str]] = []
        for a, nbrs in self._adjacency.items():
            for b in nbrs:
                key = frozenset((a, b))
                if key not in seen:
                    seen.add(key)
                    result.append((a, b))
        return result

    @property
    def device_count(self) -> int:  # V
        return len(self._adjacency)

    @property
    def connection_count(self) -> int:  # E
        return sum(len(nbrs) for nbrs in self._adjacency.values()) // 2

    def __contains__(self, name: object) -> bool:
        return self.has_device(name)

    def __len__(self) -> int:
        return self.device_count


# --------------------------------------------------------------------------------------
# Traversal records
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class TraversalStep:
    """Immutable snapshot of the algorithm state after one elementary operation.

    Attributes
    ----------
    index          : 0-based position in the step list.
    action         : 'init', 'dequeue', 'discover', 'skip', 'backtrack',
                     'found' or 'not_found'.
    current        : vertex being processed (BFS: last dequeued; DFS: stack top).
    frontier       : BFS queue (front -> back) or DFS stack (bottom -> top).
    visited        : vertices marked visited, in the order they were marked.
    order          : traversal order (BFS: dequeue order; DFS: visit order).
    tree_edges     : (parent, child) edges discovered so far.
    examined_edge  : edge being inspected in this step, if any.
    path           : final source->target path (only on the 'found' step).
    explanation    : one-sentence human-readable description.
    """

    index: int
    action: str
    current: str | None
    frontier: tuple[str, ...]
    visited: tuple[str, ...]
    order: tuple[str, ...]
    tree_edges: tuple[tuple[str, str], ...]
    examined_edge: tuple[str, str] | None
    path: tuple[str, ...]
    explanation: str


@dataclass
class TraversalResult:
    """Final outcome of a BFS or DFS run."""

    algorithm: str
    source: str
    target: str
    found: bool
    path: list[str]
    traversal_order: list[str]
    visited: list[str]
    parent: dict[str, str | None]
    edge_checks: int
    steps: list[TraversalStep] = field(default_factory=list)

    @property
    def hops(self) -> int | None:
        """Number of edges on the path, or ``None`` when no path exists."""
        return len(self.path) - 1 if self.path else None

    @property
    def path_vertex_count(self) -> int:
        return len(self.path)

    @property
    def visited_count(self) -> int:
        return len(self.visited)


class _Recorder:
    """Collects TraversalStep snapshots. A disabled recorder does nothing, so the
    algorithms can run with pure O(V) auxiliary space."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self.steps: list[TraversalStep] = []

    def record(
        self,
        action: str,
        current: str | None,
        frontier: Iterable[str],
        visited: dict[str, None],
        order: list[str],
        tree_edges: list[tuple[str, str]],
        explanation: str,
        examined_edge: tuple[str, str] | None = None,
        path: Iterable[str] = (),
    ) -> None:
        if not self.enabled:
            return
        self.steps.append(
            TraversalStep(
                index=len(self.steps),
                action=action,
                current=current,
                frontier=tuple(frontier),
                visited=tuple(visited),
                order=tuple(order),
                tree_edges=tuple(tree_edges),
                examined_edge=examined_edge,
                path=tuple(path),
                explanation=explanation,
            )
        )


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------


def _validate_endpoints(graph: NetworkGraph, source: object, target: object) -> None:
    if not isinstance(graph, NetworkGraph):
        raise GraphError("A NetworkGraph is required.")
    if graph.device_count == 0:
        raise GraphError("The network is empty - add devices before running a traversal.")
    if not isinstance(source, str) or not source:
        raise GraphError("Select a source device.")
    if not isinstance(target, str) or not target:
        raise GraphError("Select a target device.")
    if source not in graph:
        raise GraphError(f"Source device {source!r} does not exist in the network.")
    if target not in graph:
        raise GraphError(f"Target device {target!r} does not exist in the network.")


def reconstruct_path(parent: dict[str, str | None], source: str, target: str) -> list[str]:
    """Follow parent pointers from ``target`` back to ``source``.

    Returns ``[]`` when ``target`` was never reached. Runs in O(length of path).
    """
    if target not in parent:
        return []
    path: list[str] = []
    node: str | None = target
    while node is not None:
        path.append(node)
        node = parent[node]
    path.reverse()
    return path if path and path[0] == source else []


def is_valid_path(graph: NetworkGraph, path: list[str], source: str, target: str) -> bool:
    """True when ``path`` starts at source, ends at target, every consecutive
    pair is an existing connection and no vertex repeats."""
    if not path or path[0] != source or path[-1] != target:
        return False
    if len(set(path)) != len(path):
        return False
    return all(graph.has_connection(a, b) for a, b in zip(path, path[1:]))


def _fmt(nodes: Iterable[str]) -> str:
    items = list(nodes)
    return "[" + ", ".join(items) + "]" if items else "[ ]"


# --------------------------------------------------------------------------------------
# Breadth-First Search
# --------------------------------------------------------------------------------------


def bfs(
    graph: NetworkGraph, source: str, target: str, record_steps: bool = True
) -> TraversalResult:
    """Breadth-First Search from ``source`` until ``target`` is dequeued.

    Vertices are marked visited when they are ENQUEUED, so each vertex enters the
    queue at most once. Vertices leave the queue in FIFO order, i.e. in
    non-decreasing distance (number of hops) from the source, so the first time
    the target is dequeued its parent chain is a minimum-hop path.

    Time  : O(V + E) - every vertex is enqueued/dequeued at most once (O(V)) and
            the adjacency list of each dequeued vertex is scanned once; the
            lengths of all adjacency lists sum to 2E (O(E)).
    Space : O(V) auxiliary - queue, visited set and parent map each hold at most
            V entries. (Step recording, if enabled, is extra - see module doc.)
    """
    _validate_endpoints(graph, source, target)
    rec = _Recorder(record_steps)

    visited: dict[str, None] = {source: None}  # ordered set: O(1) membership
    parent: dict[str, str | None] = {source: None}
    queue: deque[str] = deque([source])
    order: list[str] = []
    tree_edges: list[tuple[str, str]] = []
    edge_checks = 0

    rec.record(
        "init", None, queue, visited, order, tree_edges,
        f"Initialise: enqueue source {source} and mark it visited. Queue = [{source}].",
    )

    while queue:
        current = queue.popleft()  # FIFO - O(1) with deque
        order.append(current)
        rec.record(
            "dequeue", current, queue, visited, order, tree_edges,
            f"Dequeue {current} (FIFO: the oldest discovered vertex) and check "
            f"whether it is the target.",
        )

        if current == target:
            path = reconstruct_path(parent, source, target)
            rec.record(
                "found", current, queue, visited, order, tree_edges,
                f"{current} is the target. Rebuild the path by following parent "
                f"pointers back to {source}: {' → '.join(path)} "
                f"({len(path) - 1} hop{'s' if len(path) != 2 else ''}, the minimum).",
                path=path,
            )
            return TraversalResult(
                "BFS", source, target, True, path, order, list(visited), parent,
                edge_checks, rec.steps,
            )

        for neighbour in graph.neighbors(current):
            edge_checks += 1
            edge = (current, neighbour)
            if neighbour not in visited:
                visited[neighbour] = None
                parent[neighbour] = current
                tree_edges.append(edge)
                queue.append(neighbour)
                rec.record(
                    "discover", current, queue, visited, order, tree_edges,
                    f"Edge {current} - {neighbour}: {neighbour} is unvisited → mark it "
                    f"visited, set parent[{neighbour}] = {current}, enqueue it.",
                    examined_edge=edge,
                )
            else:
                rec.record(
                    "skip", current, queue, visited, order, tree_edges,
                    f"Edge {current} - {neighbour}: {neighbour} was already visited → "
                    f"ignore it (this is what stops infinite loops on cycles).",
                    examined_edge=edge,
                )

    rec.record(
        "not_found", None, queue, visited, order, tree_edges,
        f"Queue is empty: all {len(visited)} device(s) reachable from {source} were "
        f"explored and {target} is not among them. No path exists.",
    )
    return TraversalResult(
        "BFS", source, target, False, [], order, list(visited), parent, edge_checks,
        rec.steps,
    )


# --------------------------------------------------------------------------------------
# Depth-First Search
# --------------------------------------------------------------------------------------


def dfs(
    graph: NetworkGraph, source: str, target: str, record_steps: bool = True
) -> TraversalResult:
    """Iterative Depth-First Search with an explicit stack.

    The stack always holds the current branch from the source to the vertex on
    top. For every vertex we keep an iterator over its neighbours, so each
    adjacency list is scanned exactly once in total (this mirrors recursive DFS
    without risking Python's recursion limit). A vertex is marked visited when it
    is pushed. When the top vertex has no unvisited neighbours left it is popped
    (backtracking). DFS stops as soon as the target is pushed; at that moment
    the stack *is* the discovered path, which is valid but not necessarily the
    shortest.

    Time  : O(V + E) - each vertex is pushed and popped at most once, and each
            neighbour iterator advances through its adjacency list once
            (sum of list lengths = 2E).
    Space : O(V) auxiliary - stack, visited set, parent map and the neighbour
            iterators each hold at most V entries.
    """
    _validate_endpoints(graph, source, target)
    rec = _Recorder(record_steps)

    visited: dict[str, None] = {source: None}
    parent: dict[str, str | None] = {source: None}
    stack: list[str] = [source]
    iterators: dict[str, Iterator[str]] = {source: iter(graph.neighbors(source))}
    order: list[str] = [source]
    tree_edges: list[tuple[str, str]] = []
    edge_checks = 0

    rec.record(
        "init", source, stack, visited, order, tree_edges,
        f"Initialise: push source {source} onto the stack and mark it visited.",
    )

    def finish_found(current: str) -> TraversalResult:
        path = reconstruct_path(parent, source, target)
        rec.record(
            "found", current, stack, visited, order, tree_edges,
            f"{current} is the target. The stack holds the branch that reached it: "
            f"{' → '.join(path)} ({len(path) - 1} hop{'s' if len(path) != 2 else ''}). "
            f"DFS does not guarantee this is the shortest path.",
            path=path,
        )
        return TraversalResult(
            "DFS", source, target, True, path, order, list(visited), parent,
            edge_checks, rec.steps,
        )

    if source == target:
        return finish_found(source)

    while stack:
        current = stack[-1]  # peek at the top of the stack
        neighbour = next(iterators[current], None)

        if neighbour is None:
            stack.pop()
            back_to = stack[-1] if stack else None
            rec.record(
                "backtrack", back_to, stack, visited, order, tree_edges,
                f"{current} has no unvisited neighbours left → pop it"
                + (f" and backtrack to {back_to}." if back_to else "; the stack is now empty."),
            )
            continue

        edge_checks += 1
        edge = (current, neighbour)
        if neighbour in visited:
            rec.record(
                "skip", current, stack, visited, order, tree_edges,
                f"Top of stack is {current}. Edge {current} - {neighbour}: {neighbour} "
                f"was already visited → skip it (prevents cycling).",
                examined_edge=edge,
            )
            continue

        visited[neighbour] = None
        parent[neighbour] = current
        tree_edges.append(edge)
        order.append(neighbour)
        stack.append(neighbour)
        iterators[neighbour] = iter(graph.neighbors(neighbour))
        rec.record(
            "discover", neighbour, stack, visited, order, tree_edges,
            f"Top of stack is {current}. Edge {current} - {neighbour}: {neighbour} is "
            f"unvisited → mark it visited, set parent[{neighbour}] = {current}, push "
            f"it and go deeper.",
            examined_edge=edge,
        )
        if neighbour == target:
            return finish_found(neighbour)

    rec.record(
        "not_found", None, stack, visited, order, tree_edges,
        f"Stack is empty: all {len(visited)} device(s) reachable from {source} were "
        f"explored and {target} is not among them. No path exists.",
    )
    return TraversalResult(
        "DFS", source, target, False, [], order, list(visited), parent, edge_checks,
        rec.steps,
    )


def run_traversal(
    graph: NetworkGraph, algorithm: str, source: str, target: str, record_steps: bool = True
) -> TraversalResult:
    """Dispatch to ``bfs`` or ``dfs`` by name ('BFS' / 'DFS', case-insensitive)."""
    name = (algorithm or "").strip().upper()
    if name == "BFS":
        return bfs(graph, source, target, record_steps)
    if name == "DFS":
        return dfs(graph, source, target, record_steps)
    raise GraphError("Choose an algorithm: BFS or DFS.")


# --------------------------------------------------------------------------------------
# Default simulated network
# --------------------------------------------------------------------------------------

DEFAULT_SOURCE = "Laptop-HR"
DEFAULT_TARGET = "DB-Server"

#: (name, type, normalised x, normalised y) - positions are in the range 0..1.
SAMPLE_DEVICES: tuple[tuple[str, str, float, float], ...] = (
    ("Laptop-HR", "Workstation", 0.04, 0.45),
    ("WS-Finance", "Workstation", 0.17, 0.12),
    ("Switch-A", "Switch", 0.24, 0.50),
    ("WS-Dev", "Workstation", 0.27, 0.88),
    ("Router-Core", "Router", 0.46, 0.45),
    ("Switch-B", "Switch", 0.46, 0.85),
    ("VPN-Gateway", "Gateway", 0.58, 0.10),
    ("Web-Server", "Server", 0.78, 0.08),
    ("Mail-Server", "Server", 0.90, 0.30),
    ("Firewall-Int", "Firewall", 0.68, 0.45),
    ("DB-Server", "Server", 0.95, 0.60),
    ("File-Server", "Server", 0.67, 0.86),
    ("Backup-NAS", "Server", 0.88, 0.88),
    ("Legacy-Kiosk", "Workstation", 0.05, 0.90),  # deliberately isolated
)

SAMPLE_CONNECTIONS: tuple[tuple[str, str], ...] = (
    ("Laptop-HR", "Switch-A"),
    ("Laptop-HR", "WS-Finance"),
    ("WS-Finance", "Switch-A"),
    ("Switch-A", "WS-Dev"),
    ("Switch-A", "Router-Core"),
    ("WS-Dev", "Switch-B"),
    ("Switch-B", "Router-Core"),
    ("Switch-B", "File-Server"),
    ("File-Server", "Backup-NAS"),
    ("Backup-NAS", "DB-Server"),
    ("Router-Core", "Firewall-Int"),
    ("Firewall-Int", "DB-Server"),
    ("Router-Core", "VPN-Gateway"),
    ("VPN-Gateway", "Web-Server"),
    ("Web-Server", "Mail-Server"),
    ("Mail-Server", "Firewall-Int"),
)


def build_sample_network() -> tuple[NetworkGraph, dict[str, tuple[float, float]]]:
    """Return the default simulated network and its normalised node layout."""
    graph = NetworkGraph.from_spec(
        [(name, kind) for name, kind, _, _ in SAMPLE_DEVICES], SAMPLE_CONNECTIONS
    )
    layout = {name: (x, y) for name, _, x, y in SAMPLE_DEVICES}
    return graph, layout
