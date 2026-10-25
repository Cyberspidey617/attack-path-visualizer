"""
attack_path_visualizer.py
=========================

Cybersecurity Attack Path Visualizer Using BFS and DFS
DAA Assignment 2 - GUI-Based Algorithm Implementation

Run with:   python attack_path_visualizer.py

An EDUCATIONAL SIMULATION. The application models a small enterprise network as
an undirected, unweighted graph and shows, step by step, how Breadth-First
Search and Depth-First Search explore connectivity from a (simulated)
compromised device to a target server. It performs no real network activity.

Architecture
------------
* traversal_core.py         - graph data structure + BFS/DFS (no GUI code).
* attack_path_visualizer.py - this file: Tkinter/ttk presentation layer only.

The GUI asks the core for a complete list of TraversalStep snapshots and then
simply moves an index through that list (Next / Previous / Run to end /
Auto-play). Rendering a step never re-runs the algorithm.
"""

from __future__ import annotations

import sys
import tkinter as tk
from tkinter import font as tkfont
from tkinter import messagebox, ttk

from traversal_core import (
    ALGORITHMS,
    DEFAULT_SOURCE,
    DEFAULT_TARGET,
    DEVICE_TYPES,
    TYPE_ABBREVIATIONS,
    GraphError,
    NetworkGraph,
    TraversalResult,
    TraversalStep,
    build_sample_network,
    run_traversal,
)

APP_TITLE = "Cybersecurity Attack Path Visualizer — BFS & DFS"

# ------------------------------------------------------------------------------------
# Theme
# ------------------------------------------------------------------------------------

COLORS = {
    "bg": "#0d1117",
    "canvas": "#0a0e13",
    "panel": "#161b22",
    "card": "#1c2330",
    "border": "#30363d",
    "text": "#e6edf3",
    "muted": "#8b949e",
    "accent": "#39d0d8",
    "button": "#262d38",
    "button_hover": "#323b48",
    "primary": "#1f7a3a",
    "primary_hover": "#26914a",
    "danger": "#a8302b",
    "danger_hover": "#c13a34",
    # graph states
    "node_default": "#2d333b",
    "node_outline": "#768390",
    "edge_default": "#3a4350",
    "edge_tree": "#2f81f7",
    "edge_examined": "#e3b341",
    "path": "#39d0d8",
    "source": "#3fb950",
    "target": "#f85149",
    "current": "#a371f7",
    "frontier": "#d29922",
    "visited": "#1f6feb",
}

LEGEND_ITEMS = (
    ("ring", COLORS["source"], "Source (start)"),
    ("ring", COLORS["target"], "Target"),
    ("fill", COLORS["current"], "Current node"),
    ("fill", COLORS["frontier"], "In queue / on stack"),
    ("fill", COLORS["visited"], "Visited"),
    ("fill", COLORS["path"], "Discovered path"),
    ("fill", COLORS["node_default"], "Unvisited"),
    ("line", COLORS["edge_examined"], "Edge being checked"),
    ("line", COLORS["edge_tree"], "Parent (tree) edge"),
)

CONCEPTS_TEXT = """\
## WHAT THIS TOOL SHOWS
The network is an undirected, unweighted graph G = (V, E). Each vertex is a simulated device; each edge is a connection. Starting from a (simulated) compromised device, a traversal asks: which devices can be reached, and by what route? This is a teaching simulation only - nothing is scanned or attacked.

## BREADTH-FIRST SEARCH (BFS)
• Uses a FIFO queue (collections.deque).
• Enqueue the source and mark it visited.
• Repeatedly dequeue the front vertex; for every unvisited neighbour: mark it visited, record its parent, enqueue it.
• Stop when the target is dequeued (or the queue empties - no path).
• Rebuild the path by following parent pointers from target back to source.

Why BFS gives a shortest path (fewest hops): BFS explores in "layers". All vertices 1 hop away are dequeued before any vertex 2 hops away, and so on, because the queue is FIFO. A vertex receives its parent the first time it is discovered, i.e. from the earliest (closest) layer, so the parent chain to the target has the minimum possible number of edges.

## DEPTH-FIRST SEARCH (DFS)
• Uses a LIFO stack (here an explicit Python list, so no recursion limit).
• Push the source; look at the top vertex; move to its next unvisited neighbour (mark visited, record parent, push) - going as deep as possible.
• When the top vertex has no unvisited neighbours left, pop it (backtrack).
• Stop when the target is pushed; the stack then holds the path.

Why DFS does NOT guarantee a shortest path: DFS commits to the first branch it meets and follows it to the end. It may reach the target through a long detour before ever looking at a shorter branch. In the sample network DFS finds a 6-hop route while BFS finds a 4-hop route between the same devices.

Cycles: both algorithms keep a visited set and never revisit a marked vertex, so they always terminate even when the network contains loops.

## TIME COMPLEXITY  -  O(V + E) for both
V = number of vertices (devices), E = number of edges (connections).
• Every vertex is marked visited at most once, so it is enqueued/dequeued (BFS) or pushed/popped (DFS) at most once: O(V).
• Each processed vertex scans its adjacency list once. In an undirected graph each edge appears in two lists, so all lists together contain 2E entries: O(E).
• Total: O(V + E). (With an adjacency matrix it would be O(V²).)

## AUXILIARY SPACE  -  O(V) for both
• BFS: queue ≤ V, visited set ≤ V, parent map ≤ V.
• DFS: stack ≤ V, visited set ≤ V, parent map ≤ V, neighbour iterators ≤ V.
• Graph storage itself (adjacency list) is O(V + E), but that is the input, not auxiliary space.

## ALGORITHM SPACE vs. GUI PLAYBACK STORAGE
To support Previous/Next, the program records a snapshot after every elementary operation. Each snapshot copies the queue/stack, visited set, order and tree edges - O(V) each - and there are O(V + E) snapshots, so playback history uses O((V + E)·V) extra memory. This cost belongs to the visualisation, not to BFS/DFS. The core functions accept record_steps=False, in which case only the O(V) auxiliary space above is used.

## HOW TO READ THE CANVAS
• Green ring = source, red ring = target.
• Purple fill = vertex being processed now.
• Amber fill = waiting in the queue (BFS) / on the current stack branch (DFS).
• Blue fill = already visited.
• Cyan = final discovered path.
• Small numbered badge = position in the traversal order.
• Dashed amber edge = the edge examined in this step; blue edges = parent pointers.
"""


def _pick_font(root: tk.Misc, candidates: tuple[str, ...], fallback: str) -> str:
    available = {f.lower() for f in tkfont.families(root)}
    for name in candidates:
        if name.lower() in available:
            return name
    return fallback


# ------------------------------------------------------------------------------------
# Small reusable widgets
# ------------------------------------------------------------------------------------


class ScrollableFrame(ttk.Frame):
    """A vertically scrollable container (canvas + inner frame + scrollbar)."""

    def __init__(self, parent: tk.Misc, background: str, **kwargs) -> None:
        super().__init__(parent, **kwargs)
        self._canvas = tk.Canvas(self, background=background, highlightthickness=0, bd=0)
        self._scrollbar = ttk.Scrollbar(self, orient="vertical", command=self._canvas.yview)
        self.inner = ttk.Frame(self._canvas, style="Card.TFrame")
        self._window = self._canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self._canvas.configure(yscrollcommand=self._scrollbar.set)
        self._canvas.pack(side="left", fill="both", expand=True)
        self._scrollbar.pack(side="right", fill="y")
        self.inner.bind("<Configure>", self._on_inner_configure)
        self._canvas.bind("<Configure>", self._on_canvas_configure)
        self.bind("<Enter>", self._bind_wheel)
        self.bind("<Leave>", self._unbind_wheel)

    def scroll_to(self, widget: tk.Misc | None) -> None:
        """Scroll so that ``widget`` (a child of ``inner``) is at the top; None = top."""
        self.update_idletasks()
        total = self.inner.winfo_height()
        if widget is None or total <= 0:
            self._canvas.yview_moveto(0)
        else:
            self._canvas.yview_moveto(max(0.0, (widget.winfo_y() - 6) / total))

    def _on_inner_configure(self, _event: tk.Event) -> None:
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))

    def _on_canvas_configure(self, event: tk.Event) -> None:
        self._canvas.itemconfigure(self._window, width=event.width)

    def _bind_wheel(self, _event: tk.Event) -> None:
        self.bind_all("<MouseWheel>", self._on_wheel)
        self.bind_all("<Button-4>", self._on_wheel)
        self.bind_all("<Button-5>", self._on_wheel)

    def _unbind_wheel(self, _event: tk.Event) -> None:
        self.unbind_all("<MouseWheel>")
        self.unbind_all("<Button-4>")
        self.unbind_all("<Button-5>")

    def _on_wheel(self, event: tk.Event) -> None:
        if self.inner.winfo_height() <= self._canvas.winfo_height():
            return
        if getattr(event, "num", None) == 4:
            delta = -1
        elif getattr(event, "num", None) == 5:
            delta = 1
        else:
            delta = -1 if event.delta > 0 else 1
        self._canvas.yview_scroll(delta * 2, "units")


# ------------------------------------------------------------------------------------
# Main application
# ------------------------------------------------------------------------------------


class AttackPathVisualizerApp:
    """Tkinter front end. Holds the graph, the node layout and the step list."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.graph: NetworkGraph
        self.layout: dict[str, tuple[float, float]]
        self.graph, self.layout = build_sample_network()

        self.result: TraversalResult | None = None
        self.step_index: int = -1
        self._play_job: str | None = None
        self._drag_node: str | None = None
        self._item_to_node: dict[int, str] = {}
        self._syncing_log = False
        self._suspend_traces = False
        #: Optional callable(str) used instead of a message box (used by tests).
        self.error_handler = None

        self.scale = max(1.0, root.winfo_fpixels("1i") / 96.0)
        ui_family = _pick_font(root, ("Segoe UI", "Inter", "Helvetica Neue", "Arial"), "DejaVu Sans")
        mono_family = _pick_font(root, ("Cascadia Mono", "Consolas", "JetBrains Mono", "Menlo"), "DejaVu Sans Mono")
        self.fonts = {
            "ui": (ui_family, 10),
            "ui_bold": (ui_family, 10, "bold"),
            "small": (ui_family, 9),
            "title": (ui_family, 16, "bold"),
            "subtitle": (ui_family, 10),
            "section": (ui_family, 11, "bold"),
            "mono": (mono_family, 10),
            "banner": (ui_family, 11),
            "node_abbr": (ui_family, 9, "bold"),
            "node_label": (ui_family, 9, "bold"),
            "badge": (ui_family, 8, "bold"),
        }

        self._configure_root()
        self._configure_style()
        self._build_layout()
        self._refresh_device_lists()
        self.source_var.set(DEFAULT_SOURCE)
        self.target_var.set(DEFAULT_TARGET)
        self._bind_shortcuts()
        self._update_panels()
        self._set_status("Ready. Choose source, target and algorithm, then press Generate Steps.")

    # ==================================================================================
    # Window and style
    # ==================================================================================

    def _configure_root(self) -> None:
        self.root.title(APP_TITLE)
        self.root.configure(background=COLORS["bg"])
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        width = min(int(1440 * self.scale), int(screen_w * 0.94))
        height = min(int(860 * self.scale), int(screen_h * 0.90))
        self.root.geometry(f"{width}x{height}+{max(0, (screen_w - width) // 2)}+{max(0, (screen_h - height) // 3)}")
        self.root.minsize(min(int(1080 * self.scale), int(screen_w * 0.9)), min(int(640 * self.scale), int(screen_h * 0.85)))

    def _configure_style(self) -> None:
        c = COLORS
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(
            ".", background=c["bg"], foreground=c["text"], fieldbackground=c["card"],
            bordercolor=c["border"], lightcolor=c["border"], darkcolor=c["border"],
            troughcolor=c["panel"], focuscolor=c["accent"], font=self.fonts["ui"],
            selectbackground=c["visited"], selectforeground=c["text"],
        )
        style.configure("TFrame", background=c["bg"])
        style.configure("Panel.TFrame", background=c["panel"])
        style.configure("Card.TFrame", background=c["card"])
        style.configure("TLabel", background=c["card"], foreground=c["text"])
        style.configure("Bg.TLabel", background=c["bg"], foreground=c["text"])
        style.configure("Title.TLabel", background=c["bg"], foreground=c["text"], font=self.fonts["title"])
        style.configure("Subtitle.TLabel", background=c["bg"], foreground=c["muted"], font=self.fonts["subtitle"])
        style.configure("Badge.TLabel", background=c["panel"], foreground=c["accent"], font=self.fonts["small"], padding=(8, 3))
        style.configure("Section.TLabel", background=c["card"], foreground=c["accent"], font=self.fonts["section"])
        style.configure("Field.TLabel", background=c["card"], foreground=c["muted"], font=self.fonts["small"])
        style.configure("Value.TLabel", background=c["card"], foreground=c["text"], font=self.fonts["ui_bold"])
        style.configure("Mono.TLabel", background=c["card"], foreground=c["text"], font=self.fonts["mono"])
        style.configure("Status.TLabel", background=c["panel"], foreground=c["muted"], font=self.fonts["small"], padding=(10, 4))
        style.configure("Banner.TLabel", background=c["panel"], foreground=c["text"], font=self.fonts["banner"], padding=(12, 8))

        style.configure("TButton", background=c["button"], foreground=c["text"], bordercolor=c["border"],
                        padding=(10, 6), relief="flat", font=self.fonts["ui"])
        style.map("TButton",
                  background=[("disabled", c["panel"]), ("pressed", c["border"]), ("active", c["button_hover"])],
                  foreground=[("disabled", "#59616b")])
        style.configure("Primary.TButton", background=c["primary"], font=self.fonts["ui_bold"])
        style.map("Primary.TButton", background=[("disabled", c["panel"]), ("active", c["primary_hover"])])
        style.configure("Danger.TButton", background=c["danger"])
        style.map("Danger.TButton", background=[("disabled", c["panel"]), ("active", c["danger_hover"])])

        style.configure("TCombobox", fieldbackground=c["bg"], background=c["button"], foreground=c["text"],
                        arrowcolor=c["text"], bordercolor=c["border"], padding=4)
        style.map("TCombobox",
                  fieldbackground=[("readonly", c["bg"]), ("disabled", c["panel"])],
                  foreground=[("readonly", c["text"]), ("disabled", c["muted"])],
                  selectbackground=[("readonly", c["bg"])], selectforeground=[("readonly", c["text"])],
                  background=[("active", c["button_hover"])])
        self.root.option_add("*TCombobox*Listbox.background", c["card"])
        self.root.option_add("*TCombobox*Listbox.foreground", c["text"])
        self.root.option_add("*TCombobox*Listbox.selectBackground", c["visited"])
        self.root.option_add("*TCombobox*Listbox.selectForeground", c["text"])
        self.root.option_add("*TCombobox*Listbox.font", self.fonts["ui"])

        style.configure("TEntry", fieldbackground=c["bg"], foreground=c["text"], insertcolor=c["text"], padding=4)
        style.configure("TRadiobutton", background=c["card"], foreground=c["text"], indicatorbackground=c["bg"],
                        indicatorforeground=c["accent"], font=self.fonts["ui"])
        style.map("TRadiobutton", background=[("active", c["card"])],
                  indicatorbackground=[("selected", c["accent"])])
        style.configure("TNotebook", background=c["bg"], borderwidth=0, tabmargins=(0, 0, 0, 0))
        style.configure("TNotebook.Tab", background=c["panel"], foreground=c["muted"], padding=(14, 6),
                        bordercolor=c["border"], font=self.fonts["ui_bold"])
        style.map("TNotebook.Tab", background=[("selected", c["card"])], foreground=[("selected", c["accent"])])
        style.configure("Treeview", background=c["card"], fieldbackground=c["card"], foreground=c["text"],
                        rowheight=int(22 * self.scale), bordercolor=c["border"], font=self.fonts["small"])
        style.map("Treeview", background=[("selected", c["visited"])], foreground=[("selected", c["text"])])
        style.configure("Treeview.Heading", background=c["panel"], foreground=c["accent"], relief="flat",
                        font=self.fonts["ui_bold"])
        style.map("Treeview.Heading", background=[("active", c["panel"])])
        style.configure("Horizontal.TScale", background=c["card"], troughcolor=c["bg"])
        style.configure("Vertical.TScrollbar", background=c["button"], troughcolor=c["panel"],
                        arrowcolor=c["muted"], bordercolor=c["panel"])

    # ==================================================================================
    # Layout construction
    # ==================================================================================

    def _build_layout(self) -> None:
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(1, weight=1)

        self._build_header()

        left = ttk.Notebook(self.root, width=int(285 * self.scale))
        self.left_notebook = left
        left.grid(row=1, column=0, sticky="nsw", padx=(12, 6), pady=(0, 6))
        self._build_run_tab(left)
        self._build_editor_tab(left)

        center = ttk.Frame(self.root, style="TFrame")
        center.grid(row=1, column=1, sticky="nsew", padx=6, pady=(0, 6))
        self._build_center(center)

        right = ttk.Notebook(self.root, width=int(320 * self.scale))
        right.grid(row=1, column=2, sticky="nse", padx=(6, 12), pady=(0, 6))
        self.right_notebook = right
        self._build_trace_tab(right)
        self._build_log_tab(right)
        self._build_concepts_tab(right)

        self.status_var = tk.StringVar()
        ttk.Label(self.root, textvariable=self.status_var, style="Status.TLabel", anchor="w").grid(
            row=2, column=0, columnspan=3, sticky="ew")

    def _build_header(self) -> None:
        header = ttk.Frame(self.root, style="TFrame", padding=(16, 12, 16, 10))
        header.grid(row=0, column=0, columnspan=3, sticky="ew")
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="⛨  Cybersecurity Attack Path Visualizer", style="Title.TLabel").grid(
            row=0, column=0, sticky="w")
        ttk.Label(header, text="Graph traversal with Breadth-First Search and Depth-First Search  •  "
                               "Educational simulation — no real network activity",
                  style="Subtitle.TLabel").grid(row=1, column=0, sticky="w")
        self.graph_stats_var = tk.StringVar()
        ttk.Label(header, textvariable=self.graph_stats_var, style="Badge.TLabel").grid(
            row=0, column=1, rowspan=2, sticky="e")

    def _card(self, parent: tk.Misc, title: str) -> ttk.Frame:
        frame = ttk.Frame(parent, style="Card.TFrame", padding=(12, 10))
        frame.pack(fill="x", padx=8, pady=(8, 2))
        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)
        ttk.Label(frame, text=title, style="Section.TLabel").grid(row=0, column=0, columnspan=2, sticky="w",
                                                                  pady=(0, 6))
        return frame

    # ---- left: run tab ------------------------------------------------------------

    def _build_run_tab(self, notebook: ttk.Notebook) -> None:
        scroll = ScrollableFrame(notebook, background=COLORS["card"], style="Card.TFrame")
        notebook.add(scroll, text="  Run  ")
        body = scroll.inner

        setup = self._card(body, "1  Traversal setup")
        self.source_var = tk.StringVar()
        self.target_var = tk.StringVar()
        self.algorithm_var = tk.StringVar(value="BFS")

        ttk.Label(setup, text="Source device (simulated compromised)", style="Field.TLabel").grid(
            row=1, column=0, columnspan=2, sticky="w")
        self.source_combo = ttk.Combobox(setup, textvariable=self.source_var, state="readonly")
        self.source_combo.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(2, 8))
        ttk.Label(setup, text="Target device", style="Field.TLabel").grid(row=3, column=0, columnspan=2, sticky="w")
        self.target_combo = ttk.Combobox(setup, textvariable=self.target_var, state="readonly")
        self.target_combo.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(2, 8))

        ttk.Label(setup, text="Algorithm", style="Field.TLabel").grid(row=5, column=0, columnspan=2, sticky="w")
        ttk.Radiobutton(setup, text="BFS  (queue)", value="BFS", variable=self.algorithm_var).grid(
            row=6, column=0, sticky="w", pady=2)
        ttk.Radiobutton(setup, text="DFS  (stack)", value="DFS", variable=self.algorithm_var).grid(
            row=6, column=1, sticky="w", pady=2)

        self.generate_button = ttk.Button(setup, text="Generate Steps", style="Primary.TButton",
                                          command=self.generate_steps)
        self.generate_button.grid(row=7, column=0, columnspan=2, sticky="ew", pady=(10, 4))
        ttk.Button(setup, text="Compare BFS vs DFS", command=self.compare_algorithms).grid(
            row=8, column=0, columnspan=2, sticky="ew", pady=(2, 0))

        controls = self._card(body, "2  Step-by-step execution")
        self.prev_button = ttk.Button(controls, text="◀  Previous", command=self.previous_step)
        self.prev_button.grid(row=1, column=0, sticky="ew", padx=(0, 3), pady=3)
        self.next_button = ttk.Button(controls, text="Next  ▶", command=self.next_step)
        self.next_button.grid(row=1, column=1, sticky="ew", padx=(3, 0), pady=3)
        self.end_button = ttk.Button(controls, text="Run to completion  ⏭", command=self.run_to_completion)
        self.end_button.grid(row=2, column=0, columnspan=2, sticky="ew", pady=3)
        self.play_button = ttk.Button(controls, text="Auto-play  ⏵", command=self.toggle_autoplay)
        self.play_button.grid(row=3, column=0, columnspan=2, sticky="ew", pady=3)

        ttk.Label(controls, text="Auto-play delay", style="Field.TLabel").grid(row=4, column=0, sticky="w",
                                                                               pady=(6, 0))
        self.speed_var = tk.IntVar(value=700)
        self.speed_label = ttk.Label(controls, text="700 ms", style="Field.TLabel")
        self.speed_label.grid(row=4, column=1, sticky="e", pady=(6, 0))
        ttk.Scale(controls, from_=150, to=2000, variable=self.speed_var, orient="horizontal",
                  command=lambda v: self.speed_label.configure(text=f"{int(float(v))} ms")).grid(
            row=5, column=0, columnspan=2, sticky="ew")

        self.reset_button = ttk.Button(controls, text="Reset", style="Danger.TButton", command=self.reset_traversal)
        self.reset_button.grid(row=6, column=0, columnspan=2, sticky="ew", pady=(10, 0))

        ttk.Label(body, text="Keyboard: ← / → step, Home / End jump.\nTip: drag devices on the canvas\nto rearrange the layout.",
                  style="Field.TLabel", justify="left").pack(fill="x", padx=20, pady=(10, 8))

        for var in (self.source_var, self.target_var, self.algorithm_var):
            var.trace_add("write", self._on_selection_changed)

    # ---- left: editor tab -----------------------------------------------------------

    def _build_editor_tab(self, notebook: ttk.Notebook) -> None:
        scroll = ScrollableFrame(notebook, background=COLORS["card"], style="Card.TFrame")
        notebook.add(scroll, text="  Network Editor  ")
        body = scroll.inner

        add = self._card(body, "Add device")
        self.new_name_var = tk.StringVar()
        self.new_type_var = tk.StringVar(value="Workstation")
        ttk.Label(add, text="Name (max 20 chars)", style="Field.TLabel").grid(row=1, column=0, columnspan=2, sticky="w")
        name_entry = ttk.Entry(add, textvariable=self.new_name_var)
        name_entry.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(2, 6))
        name_entry.bind("<Return>", lambda _e: self.add_device())
        ttk.Label(add, text="Type", style="Field.TLabel").grid(row=3, column=0, columnspan=2, sticky="w")
        ttk.Combobox(add, textvariable=self.new_type_var, values=DEVICE_TYPES, state="readonly").grid(
            row=4, column=0, columnspan=2, sticky="ew", pady=(2, 8))
        ttk.Button(add, text="Add device", command=self.add_device).grid(row=5, column=0, columnspan=2, sticky="ew")

        conn = self._card(body, "Connections")
        self.edge_a_var = tk.StringVar()
        self.edge_b_var = tk.StringVar()
        ttk.Label(conn, text="Device A", style="Field.TLabel").grid(row=1, column=0, columnspan=2, sticky="w")
        self.edge_a_combo = ttk.Combobox(conn, textvariable=self.edge_a_var, state="readonly")
        self.edge_a_combo.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(2, 6))
        ttk.Label(conn, text="Device B", style="Field.TLabel").grid(row=3, column=0, columnspan=2, sticky="w")
        self.edge_b_combo = ttk.Combobox(conn, textvariable=self.edge_b_var, state="readonly")
        self.edge_b_combo.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(2, 8))
        ttk.Button(conn, text="Connect", command=self.add_connection).grid(row=5, column=0, sticky="ew", padx=(0, 3))
        ttk.Button(conn, text="Disconnect", command=self.remove_connection).grid(row=5, column=1, sticky="ew",
                                                                                 padx=(3, 0))

        remove = self._card(body, "Remove device")
        self.remove_var = tk.StringVar()
        self.remove_combo = ttk.Combobox(remove, textvariable=self.remove_var, state="readonly")
        self.remove_combo.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(2, 8))
        ttk.Button(remove, text="Remove device", style="Danger.TButton", command=self.remove_device).grid(
            row=2, column=0, columnspan=2, sticky="ew")

        net = self._card(body, "Network")
        ttk.Button(net, text="Load sample network", command=self.load_sample_network).grid(
            row=1, column=0, columnspan=2, sticky="ew", pady=(0, 4))
        ttk.Button(net, text="Clear all devices", style="Danger.TButton", command=self.clear_network).grid(
            row=2, column=0, columnspan=2, sticky="ew")
        ttk.Label(body, text="Editing the network resets any loaded traversal.\n"
                             "Self-connections, duplicate connections and\nduplicate names are rejected.",
                  style="Field.TLabel", justify="left").pack(fill="x", padx=20, pady=(10, 8))

    # ---- centre: canvas, banner, legend --------------------------------------------

    def _build_center(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)
        frame = tk.Frame(parent, background=COLORS["border"], bd=0)
        frame.grid(row=0, column=0, sticky="nsew")
        self.canvas = tk.Canvas(frame, background=COLORS["canvas"], highlightthickness=0, bd=0)
        self.canvas.pack(fill="both", expand=True, padx=1, pady=1)
        self.canvas.bind("<Configure>", lambda _e: self._redraw())
        self.canvas.bind("<ButtonPress-1>", self._on_canvas_press)
        self.canvas.bind("<B1-Motion>", self._on_canvas_drag)
        self.canvas.bind("<ButtonRelease-1>", self._on_canvas_release)
        self.canvas.tag_bind("node", "<Enter>", lambda _e: self.canvas.configure(cursor="fleur"))
        self.canvas.tag_bind("node", "<Leave>", lambda _e: self.canvas.configure(cursor=""))

        self.banner_var = tk.StringVar()
        self.banner = ttk.Label(parent, textvariable=self.banner_var, style="Banner.TLabel", anchor="w",
                                justify="left")
        self.banner.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        self.banner.bind("<Configure>", lambda e: self.banner.configure(wraplength=max(200, e.width - 48)))

        legend = tk.Frame(parent, background=COLORS["panel"])
        legend.grid(row=2, column=0, sticky="ew", pady=(6, 0))
        size = int(16 * self.scale)
        self._legend_cells: list[tk.Frame] = []
        self._legend_columns = 0
        legend.bind("<Configure>", self._reflow_legend)
        for i, (kind, color, label) in enumerate(LEGEND_ITEMS):
            cell = tk.Frame(legend, background=COLORS["panel"])
            self._legend_cells.append(cell)
            cell.grid(row=i // 5, column=i % 5, sticky="w", padx=8, pady=3)
            sw = tk.Canvas(cell, width=size + 4, height=size + 4, background=COLORS["panel"], highlightthickness=0)
            sw.pack(side="left")
            if kind == "ring":
                sw.create_oval(3, 3, size, size, outline=color, width=3, fill=COLORS["node_default"])
            elif kind == "fill":
                sw.create_oval(3, 3, size, size, outline=COLORS["node_outline"], fill=color)
            else:
                sw.create_line(2, size // 2 + 2, size + 2, size // 2 + 2, fill=color, width=3,
                               dash=(4, 2) if color == COLORS["edge_examined"] else None)
            tk.Label(cell, text=label, background=COLORS["panel"], foreground=COLORS["text"],
                     font=self.fonts["small"]).pack(side="left", padx=(4, 0))

    def _reflow_legend(self, event: tk.Event) -> None:
        """Re-grid the legend so it wraps instead of being clipped in narrow windows."""
        widest = max(cell.winfo_reqwidth() for cell in self._legend_cells) + 16
        columns = max(2, min(5, event.width // max(1, widest)))
        if columns == self._legend_columns:
            return
        self._legend_columns = columns
        for i, cell in enumerate(self._legend_cells):
            cell.grid_configure(row=i // columns, column=i % columns)

    # ---- right: trace, log, concepts ------------------------------------------------

    def _field(self, parent: tk.Misc, row: int, title: str, mono: bool = False) -> tuple[ttk.Label, tk.StringVar]:
        header = ttk.Label(parent, text=title, style="Field.TLabel")
        header.grid(row=row, column=0, columnspan=2, sticky="w", pady=(4, 0))
        var = tk.StringVar(value="—")
        value = ttk.Label(parent, textvariable=var, style="Mono.TLabel" if mono else "Value.TLabel",
                          wraplength=int(270 * self.scale), justify="left")
        value.grid(row=row + 1, column=0, columnspan=2, sticky="w")
        return header, var

    def _build_trace_tab(self, notebook: ttk.Notebook) -> None:
        scroll = ScrollableFrame(notebook, background=COLORS["card"], style="Card.TFrame")
        notebook.add(scroll, text=" Trace ")
        self.trace_scroll = scroll
        body = scroll.inner

        step = self._card(body, "Current step")
        _, self.step_var = self._field(step, 1, "Step")
        _, self.action_var = self._field(step, 3, "Operation")
        _, self.current_var = self._field(step, 5, "Current node")
        self.frontier_header, self.frontier_var = self._field(step, 7, "Queue (front → back)", mono=True)
        self.visited_header, self.visited_var = self._field(step, 9, "Visited set", mono=True)
        _, self.order_var = self._field(step, 11, "Traversal order", mono=True)
        _, self.explain_var = self._field(step, 13, "Explanation")

        res = self._card(body, "Result")
        self.result_card = res
        _, self.outcome_var = self._field(res, 1, "Target reached?")
        _, self.path_var = self._field(res, 3, "Discovered path", mono=True)
        _, self.hops_var = self._field(res, 5, "Edges (hops) in path")
        _, self.path_nodes_var = self._field(res, 7, "Vertices in path")
        _, self.visited_count_var = self._field(res, 9, "Total visited vertices")
        _, self.checks_var = self._field(res, 11, "Adjacency-list entries examined")

        cmp_card = self._card(body, "BFS vs DFS comparison")
        self.compare_card = cmp_card
        _, self.compare_var = self._field(cmp_card, 1, "Filled in by “Compare BFS vs DFS”", mono=True)

    def _build_log_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, style="Card.TFrame", padding=6)
        notebook.add(frame, text=" Step Log ")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        columns = ("step", "op", "node", "frontier")
        self.log_tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        for col, title, width in (("step", "#", 40), ("op", "Operation", 80), ("node", "Node", 100),
                                  ("frontier", "Queue / Stack", 160)):
            self.log_tree.heading(col, text=title)
            self.log_tree.column(col, width=int(width * self.scale), anchor="w", stretch=(col == "frontier"))
        self.log_tree.grid(row=0, column=0, sticky="nsew")
        sb = ttk.Scrollbar(frame, orient="vertical", command=self.log_tree.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self.log_tree.configure(yscrollcommand=sb.set)
        self.log_tree.bind("<<TreeviewSelect>>", self._on_log_select)
        ttk.Label(frame, text="Click a row to jump to that step.", style="Field.TLabel").grid(
            row=1, column=0, columnspan=2, sticky="w", pady=(4, 0))

    def _build_concepts_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, style="Card.TFrame", padding=6)
        notebook.add(frame, text=" Concepts ")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        text = tk.Text(frame, wrap="word", background=COLORS["card"], foreground=COLORS["text"],
                       insertbackground=COLORS["text"], relief="flat", font=self.fonts["small"],
                       padx=8, pady=6, spacing1=1, spacing3=2, highlightthickness=0)
        text.grid(row=0, column=0, sticky="nsew")
        sb = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        sb.grid(row=0, column=1, sticky="ns")
        text.configure(yscrollcommand=sb.set)
        text.tag_configure("heading", foreground=COLORS["accent"], font=self.fonts["ui_bold"], spacing1=8)
        for line in CONCEPTS_TEXT.splitlines():
            if line.startswith("## "):
                text.insert("end", line[3:] + "\n", ("heading",))
            else:
                text.insert("end", line + "\n")
        text.configure(state="disabled")

    # ==================================================================================
    # Shortcuts and small helpers
    # ==================================================================================

    def _bind_shortcuts(self) -> None:
        def guarded(action):
            def handler(event: tk.Event) -> None:
                if isinstance(event.widget, (ttk.Entry, tk.Entry, ttk.Combobox, tk.Text)):
                    return
                action()
            return handler

        self.root.bind("<Right>", guarded(self.next_step))
        self.root.bind("<Left>", guarded(self.previous_step))
        self.root.bind("<Home>", guarded(lambda: self.go_to_step(0)))
        self.root.bind("<End>", guarded(self.run_to_completion))

    def _set_status(self, message: str) -> None:
        self.status_var.set(message)

    def _error(self, message: str) -> None:
        self._set_status("⚠  " + message)
        if self.error_handler is not None:
            self.error_handler(message)
        else:
            messagebox.showerror("Invalid input", message, parent=self.root)

    def _current_step(self) -> TraversalStep | None:
        if self.result is None or not (0 <= self.step_index < len(self.result.steps)):
            return None
        return self.result.steps[self.step_index]

    # ==================================================================================
    # Traversal control
    # ==================================================================================

    def generate_steps(self) -> bool:
        """Validate inputs, run the selected algorithm and show step 1."""
        self._stop_autoplay()
        try:
            result = run_traversal(self.graph, self.algorithm_var.get(), self.source_var.get(),
                                   self.target_var.get(), record_steps=True)
        except GraphError as exc:
            self._error(str(exc))
            return False
        self.result = result
        self._fill_log()
        self.go_to_step(0)
        self._set_status(f"{result.algorithm} generated {len(result.steps)} steps from {result.source} to "
                         f"{result.target}. Use Next / Previous, Auto-play or Run to completion.")
        return True

    def go_to_step(self, index: int) -> None:
        if self.result is None:
            return
        index = max(0, min(index, len(self.result.steps) - 1))
        previous = self.step_index
        self.step_index = index
        self._sync_log_selection()
        self._update_panels()
        self._redraw()
        last = len(self.result.steps) - 1
        if index == last and previous != last:
            self.trace_scroll.scroll_to(self.result_card)  # reveal the result
        elif index == 0:
            self.trace_scroll.scroll_to(None)

    def next_step(self) -> None:
        if self.result is None:
            self._set_status("Generate steps first.")
            return
        if self.step_index < len(self.result.steps) - 1:
            self.go_to_step(self.step_index + 1)
        else:
            self._stop_autoplay()
            self._set_status("Already at the final step.")

    def previous_step(self) -> None:
        if self.result is None:
            self._set_status("Generate steps first.")
            return
        self._stop_autoplay()
        if self.step_index > 0:
            self.go_to_step(self.step_index - 1)
        else:
            self._set_status("Already at the first step.")

    def run_to_completion(self) -> None:
        if self.result is None and not self.generate_steps():
            return
        self._stop_autoplay()
        assert self.result is not None
        self.go_to_step(len(self.result.steps) - 1)

    def toggle_autoplay(self) -> None:
        if self._play_job is not None:
            self._stop_autoplay()
            return
        if self.result is None and not self.generate_steps():
            return
        assert self.result is not None
        if self.step_index >= len(self.result.steps) - 1:
            self.go_to_step(0)
        self.play_button.configure(text="Pause  ⏸")
        self._schedule_play()

    def _schedule_play(self) -> None:
        self._play_job = self.root.after(int(self.speed_var.get()), self._play_tick)

    def _play_tick(self) -> None:
        self._play_job = None
        if self.result is None or self.step_index >= len(self.result.steps) - 1:
            self._stop_autoplay()
            return
        self.go_to_step(self.step_index + 1)
        if self.step_index < len(self.result.steps) - 1:
            self._schedule_play()
        else:
            self._stop_autoplay()

    def _stop_autoplay(self) -> None:
        if self._play_job is not None:
            self.root.after_cancel(self._play_job)
            self._play_job = None
        if hasattr(self, "play_button"):
            self.play_button.configure(text="Auto-play  ⏵")

    def reset_traversal(self, message: str | None = "Traversal reset.") -> None:
        self._stop_autoplay()
        self.result = None
        self.step_index = -1
        self.log_tree.delete(*self.log_tree.get_children())
        self._update_panels()
        self._redraw()
        if message:
            self._set_status(message)

    def compare_algorithms(self) -> None:
        """Run both algorithms (without step recording) and summarise the difference."""
        source, target = self.source_var.get(), self.target_var.get()
        try:
            bfs_res = run_traversal(self.graph, "BFS", source, target, record_steps=False)
            dfs_res = run_traversal(self.graph, "DFS", source, target, record_steps=False)
        except GraphError as exc:
            self._error(str(exc))
            return

        def line(r: TraversalResult) -> str:
            if not r.found:
                return f"{r.algorithm}: no path\n  visited {r.visited_count}, checks {r.edge_checks}"
            return (f"{r.algorithm}: {r.hops} hop(s)\n  visited {r.visited_count}, checks {r.edge_checks}\n"
                    f"  {' → '.join(r.path)}")

        verdict = ""
        if bfs_res.found and dfs_res.found:
            if dfs_res.hops == bfs_res.hops:
                verdict = "\nBoth found a minimum-hop path this time."
            else:
                verdict = (f"\nDFS path is {dfs_res.hops - bfs_res.hops} hop(s) longer — "
                           f"DFS does not guarantee the shortest path.")
        elif not bfs_res.found:
            verdict = "\nTarget unreachable: both report no path."
        self.compare_var.set(f"{line(bfs_res)}\n{line(dfs_res)}{verdict}")
        self.right_notebook.select(0)
        self.trace_scroll.scroll_to(self.compare_card)
        self._set_status(f"Compared BFS and DFS from {source} to {target}.")

    # ==================================================================================
    # Network editor actions
    # ==================================================================================

    def add_device(self) -> None:
        try:
            name = self.graph.add_device(self.new_name_var.get(), self.new_type_var.get())
        except GraphError as exc:
            self._error(str(exc))
            return
        self.layout[name] = self._free_position()
        self.new_name_var.set("")
        self._on_graph_changed(f"Added device '{name}'. Connect it in the Connections section.")

    def remove_device(self) -> None:
        name = self.remove_var.get()
        if not name:
            self._error("Select a device to remove.")
            return
        try:
            self.graph.remove_device(name)
        except GraphError as exc:
            self._error(str(exc))
            return
        self.layout.pop(name, None)
        self.remove_var.set("")
        self._on_graph_changed(f"Removed device '{name}' and its connections.")

    def add_connection(self) -> None:
        a, b = self.edge_a_var.get(), self.edge_b_var.get()
        if not a or not b:
            self._error("Select both Device A and Device B.")
            return
        try:
            self.graph.add_connection(a, b)
        except GraphError as exc:
            self._error(str(exc))
            return
        self._on_graph_changed(f"Connected {a} ↔ {b}.")

    def remove_connection(self) -> None:
        a, b = self.edge_a_var.get(), self.edge_b_var.get()
        if not a or not b:
            self._error("Select both Device A and Device B.")
            return
        try:
            self.graph.remove_connection(a, b)
        except GraphError as exc:
            self._error(str(exc))
            return
        self._on_graph_changed(f"Disconnected {a} ↔ {b}.")

    def load_sample_network(self) -> None:
        self.graph, self.layout = build_sample_network()
        self._on_graph_changed("Sample network loaded.")
        self.source_var.set(DEFAULT_SOURCE)
        self.target_var.set(DEFAULT_TARGET)

    def clear_network(self, confirm: bool = True) -> None:
        if confirm and self.graph.device_count and not messagebox.askyesno(
                "Clear network", "Remove every device and connection?", parent=self.root):
            return
        self.graph = NetworkGraph()
        self.layout = {}
        self._on_graph_changed("Network cleared. Add devices or load the sample network.")

    def _on_graph_changed(self, message: str) -> None:
        self._refresh_device_lists()
        self.reset_traversal(message=None)
        self.compare_var.set("—")
        self._set_status(message)

    def _refresh_device_lists(self) -> None:
        names = self.graph.devices()
        self._suspend_traces = True
        try:
            for combo, var in ((self.source_combo, self.source_var), (self.target_combo, self.target_var),
                               (self.edge_a_combo, self.edge_a_var), (self.edge_b_combo, self.edge_b_var),
                               (self.remove_combo, self.remove_var)):
                combo.configure(values=names)
                if var.get() not in names:
                    var.set("")
        finally:
            self._suspend_traces = False
        self.graph_stats_var.set(f"V = {self.graph.device_count}   E = {self.graph.connection_count}")

    def _on_selection_changed(self, *_args) -> None:
        if self._suspend_traces:
            return
        self.compare_var.set("—")  # any earlier comparison no longer applies
        if self.result is not None:
            self.reset_traversal(message="Selection changed — press Generate Steps to run again.")
        else:
            self._redraw()

    def _free_position(self) -> tuple[float, float]:
        """Pick the grid point farthest from every existing node (avoids overlap)."""
        candidates = [(0.05 + 0.9 * i / 8, 0.06 + 0.88 * j / 5) for i in range(9) for j in range(6)]
        if not self.layout:
            return (0.5, 0.5)
        width = max(self.canvas.winfo_width(), 400)
        height = max(self.canvas.winfo_height(), 300)
        aspect = width / height

        def clearance(p: tuple[float, float]) -> float:
            return min(((p[0] - q[0]) * aspect) ** 2 + (p[1] - q[1]) ** 2 for q in self.layout.values())

        return max(candidates, key=clearance)

    # ==================================================================================
    # Panels
    # ==================================================================================

    def _fill_log(self) -> None:
        self.log_tree.delete(*self.log_tree.get_children())
        if self.result is None:
            return
        for step in self.result.steps:
            self.log_tree.insert("", "end", iid=str(step.index), values=(
                step.index + 1, step.action.upper().replace("_", " "), step.current or "—",
                ", ".join(step.frontier) or "∅"))

    def _sync_log_selection(self) -> None:
        if self.result is None:
            return
        iid = str(self.step_index)
        self._syncing_log = True
        try:
            self.log_tree.selection_set(iid)
            self.log_tree.see(iid)
        finally:
            self._syncing_log = False

    def _on_log_select(self, _event: tk.Event) -> None:
        if self._syncing_log:
            return
        selection = self.log_tree.selection()
        # <<TreeviewSelect>> is delivered asynchronously, so a selection we made
        # ourselves in _sync_log_selection arrives here too: ignore it.
        if selection and int(selection[0]) != self.step_index:
            self._stop_autoplay()
            self.go_to_step(int(selection[0]))

    def _update_panels(self) -> None:
        algorithm = self.result.algorithm if self.result else self.algorithm_var.get()
        self.frontier_header.configure(text="Queue (front → back)" if algorithm == "BFS"
                                       else "Stack (bottom → top)")
        step = self._current_step()
        has_steps = step is not None
        for button in (self.prev_button, self.next_button, self.reset_button):
            button.state(["!disabled"] if has_steps else ["disabled"])

        if step is None:
            for var in (self.action_var, self.current_var, self.frontier_var, self.visited_var, self.order_var,
                        self.outcome_var, self.path_var, self.hops_var, self.path_nodes_var,
                        self.visited_count_var, self.checks_var):
                var.set("—")
            self.step_var.set("0 / 0")
            self.explain_var.set("Press Generate Steps to build the traversal.")
            self.banner_var.set("Select a source, a target and BFS or DFS, then press Generate Steps.  "
                                "Green ring = source, red ring = target.")
            self.visited_header.configure(text="Visited set")
            return

        assert self.result is not None
        total = len(self.result.steps)
        self.prev_button.state(["!disabled"] if self.step_index > 0 else ["disabled"])
        self.next_button.state(["!disabled"] if self.step_index < total - 1 else ["disabled"])
        self.step_var.set(f"{self.step_index + 1} / {total}   ({self.result.algorithm})")
        self.action_var.set(step.action.upper().replace("_", " "))
        self.current_var.set(step.current or "—")
        self.frontier_var.set("[ " + ", ".join(step.frontier) + " ]" if step.frontier else "[ ] (empty)")
        self.visited_header.configure(text=f"Visited set  ({len(step.visited)})")
        self.visited_var.set("{ " + ", ".join(step.visited) + " }")
        self.order_var.set(" → ".join(step.order) if step.order else "—")
        self.explain_var.set(step.explanation)
        self.banner_var.set(f"Step {self.step_index + 1}/{total}  •  {step.explanation}")

        final = self.step_index == total - 1
        r = self.result
        if not final:
            self.outcome_var.set("Traversal in progress… (result shown at the final step)")
            for var in (self.path_var, self.hops_var, self.path_nodes_var, self.visited_count_var,
                        self.checks_var):
                var.set("—")
            return
        if r.found:
            self.outcome_var.set(f"YES — {r.target} reached from {r.source}")
            self.path_var.set(" → ".join(r.path))
            note = "  (minimum — BFS)" if r.algorithm == "BFS" else "  (not guaranteed minimum — DFS)"
            self.hops_var.set(f"{r.hops}{note}")
            self.path_nodes_var.set(str(r.path_vertex_count))
        else:
            self.outcome_var.set(f"NO — no path exists from {r.source} to {r.target}")
            self.path_var.set("No path (target is in a different connected component)")
            self.hops_var.set("—")
            self.path_nodes_var.set("0")
        self.visited_count_var.set(f"{r.visited_count} of {self.graph.device_count} devices")
        self.checks_var.set(f"{r.edge_checks}  (upper bound 2E = {2 * self.graph.connection_count})")

    # ==================================================================================
    # Canvas drawing
    # ==================================================================================

    def _to_canvas(self, name: str) -> tuple[float, float]:
        w = max(self.canvas.winfo_width(), 200)
        h = max(self.canvas.winfo_height(), 200)
        mx, top, bottom = 60 * self.scale, 50 * self.scale, 62 * self.scale
        nx, ny = self.layout.get(name, (0.5, 0.5))
        return mx + nx * (w - 2 * mx), top + ny * (h - top - bottom)

    def _from_canvas(self, x: float, y: float) -> tuple[float, float]:
        w = max(self.canvas.winfo_width(), 200)
        h = max(self.canvas.winfo_height(), 200)
        mx, top, bottom = 60 * self.scale, 50 * self.scale, 62 * self.scale
        nx = (x - mx) / max(1.0, w - 2 * mx)
        ny = (y - top) / max(1.0, h - top - bottom)
        return min(1.0, max(0.0, nx)), min(1.0, max(0.0, ny))

    def _redraw(self) -> None:
        c = self.canvas
        c.delete("all")
        self._item_to_node.clear()
        w = max(c.winfo_width(), 200)
        h = max(c.winfo_height(), 200)

        if self.graph.device_count == 0:
            c.create_text(w / 2, h / 2, text="The network is empty.\nAdd devices in the Network Editor tab "
                                             "or load the sample network.",
                          fill=COLORS["muted"], font=self.fonts["banner"], justify="center")
            return

        step = self._current_step()
        frontier = set(step.frontier) if step else set()
        visited = set(step.visited) if step else set()
        order_pos = {n: i + 1 for i, n in enumerate(step.order)} if step else {}
        tree = {frozenset(e) for e in step.tree_edges} if step else set()
        path = list(step.path) if step else []
        path_set = set(path)
        path_edges = {frozenset(p) for p in zip(path, path[1:])}
        examined = frozenset(step.examined_edge) if step and step.examined_edge else None
        current = step.current if step else None
        source, target = self.source_var.get(), self.target_var.get()
        # Shrink nodes and labels when the canvas is small so labels stay readable.
        k = max(0.65, min(1.0, w / (700 * self.scale), h / (560 * self.scale)))
        s = self.scale * k
        family = self.fonts["node_label"][0]
        abbr_font = (family, max(7, round(9 * k)), "bold")
        label_font = (family, max(7, round(9 * k)), "bold")
        badge_font = (family, max(6, round(8 * k)), "bold")

        # --- edges (drawn first so nodes sit on top) ---
        for a, b in self.graph.connections():
            key = frozenset((a, b))
            x1, y1 = self._to_canvas(a)
            x2, y2 = self._to_canvas(b)
            color, width, dash = COLORS["edge_default"], 2 * s, None
            if key in path_edges:
                color, width = COLORS["path"], 6 * s
            elif key == examined:
                color, width, dash = COLORS["edge_examined"], 4 * s, (8, 4)
            elif key in tree:
                color, width = COLORS["edge_tree"], 3 * s
            c.create_line(x1, y1, x2, y2, fill=color, width=width, dash=dash, capstyle="round")

        # --- nodes ---
        r = 21 * s
        for name in self.graph.devices():
            x, y = self._to_canvas(name)
            if name in path_set:
                fill, ink = COLORS["path"], "#06222a"
            elif name == current:
                fill, ink = COLORS["current"], "#ffffff"
            elif name in frontier:
                fill, ink = COLORS["frontier"], "#1b1300"
            elif name in visited:
                fill, ink = COLORS["visited"], "#ffffff"
            else:
                fill, ink = COLORS["node_default"], COLORS["text"]

            items = []
            ring = r + 5 * s
            if name == source:
                items.append(c.create_oval(x - ring, y - ring, x + ring, y + ring, outline=COLORS["source"],
                                           width=4 * s, tags=("node",)))
            if name == target:
                rr = ring + (6 * s if name == source else 0)
                items.append(c.create_oval(x - rr, y - rr, x + rr, y + rr, outline=COLORS["target"],
                                           width=4 * s, dash=(6, 3) if name == source else None, tags=("node",)))
            if name == current and name not in path_set:
                glow = r + 3 * s
                items.append(c.create_oval(x - glow, y - glow, x + glow, y + glow, outline="#d2b8ff",
                                           width=2 * s, tags=("node",)))
            items.append(c.create_oval(x - r, y - r, x + r, y + r, fill=fill, outline=COLORS["node_outline"],
                                       width=1.5 * s, tags=("node",)))
            items.append(c.create_text(x, y, text=TYPE_ABBREVIATIONS.get(self.graph.device_type(name), "?"),
                                       fill=ink, font=abbr_font, tags=("node",)))
            label_y = y + r + (13 if name in (source, target) else 7) * s
            label = c.create_text(x, label_y, text=name, fill=COLORS["text"], font=label_font,
                                  anchor="n", tags=("node",))
            x0, y0, x1, y1 = c.bbox(label)
            plate = c.create_rectangle(x0 - 4, y0 - 1, x1 + 4, y1 + 1, fill=COLORS["canvas"], outline="",
                                       tags=("node",))
            c.tag_lower(plate, label)
            items += [label, plate]
            if name in order_pos:
                bx, by, br = x + r * 0.85, y - r * 0.85, 9 * s
                items.append(c.create_oval(bx - br, by - br, bx + br, by + br, fill=COLORS["bg"],
                                           outline=COLORS["accent"], width=1.5, tags=("node",)))
                items.append(c.create_text(bx, by, text=str(order_pos[name]), fill=COLORS["accent"],
                                           font=badge_font, tags=("node",)))
            for item in items:
                self._item_to_node[item] = name

        # --- overlay ---
        if self.result is not None and step is not None:
            info = f"{self.result.algorithm}  •  step {self.step_index + 1} / {len(self.result.steps)}"
        else:
            info = "No traversal loaded"
        c.create_text(14, 12, text=info, anchor="nw", fill=COLORS["muted"], font=self.fonts["small"])
        if w > 640 * self.scale:
            c.create_text(w - 14, 12, text="Simulated network — educational use only", anchor="ne",
                          fill=COLORS["muted"], font=self.fonts["small"])

    # ---- dragging -------------------------------------------------------------------

    def _on_canvas_press(self, _event: tk.Event) -> None:
        current = self.canvas.find_withtag("current")
        self._drag_node = self._item_to_node.get(current[0]) if current else None

    def _on_canvas_drag(self, event: tk.Event) -> None:
        if self._drag_node and self._drag_node in self.layout:
            self.layout[self._drag_node] = self._from_canvas(event.x, event.y)
            self._redraw()

    def _on_canvas_release(self, _event: tk.Event) -> None:
        self._drag_node = None


def main() -> None:
    if sys.platform.startswith("win"):
        try:  # crisp text on high-DPI Windows displays
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:  # noqa: BLE001 - harmless if unavailable
            pass
    root = tk.Tk()
    AttackPathVisualizerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
