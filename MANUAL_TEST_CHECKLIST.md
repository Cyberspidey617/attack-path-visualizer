# Manual GUI Verification Checklist (Windows)

Run `python attack_path_visualizer.py` from the project folder and tick each item.
Items marked ✔ were verified by the developer on Linux under a virtual display; every item still needs one pass on your Windows machine.

| # | Area | Action | Expected result | Linux | Windows |
|---|---|---|---|---|---|
| 1 | Startup | Launch the program | Dark window opens; 14 devices drawn; badge shows V = 14, E = 16; Laptop-HR has a green ring, DB-Server a red ring; no errors in the console | ✔ | ☐ |
| 2 | Selection | Change Source / Target dropdowns | Rings move to the chosen devices immediately | ✔ | ☐ |
| 3 | BFS | BFS, Laptop-HR → DB-Server, Generate Steps | "Step 1 / 36"; Queue = [Laptop-HR] | ✔ | ☐ |
| 4 | Next | Press Next several times (or →) | Queue changes FIFO; amber = queued, blue = visited, purple = current; numbered badges appear | ✔ | ☐ |
| 5 | Previous | Press Previous (or ←) | Returns exactly to the earlier state; Previous disabled at step 1 | ✔ | ☐ |
| 6 | Run to completion | Press Run to completion | Step 36/36; path Laptop-HR → Switch-A → Router-Core → Firewall-Int → DB-Server in cyan; 4 hops; 13 of 14 visited | ✔ | ☐ |
| 7 | DFS | Select DFS, Run to completion | 18 steps; 6-hop path via WS-Dev and Switch-B; Stack (bottom → top) label; note "not guaranteed minimum" | ✔ | ☐ |
| 8 | Compare | Press Compare BFS vs DFS | BFS 4 hops, DFS 6 hops, "DFS path is 2 hop(s) longer" | ✔ | ☐ |
| 9 | Auto-play | Press Auto-play, move the delay slider, press Pause | Steps advance automatically; pause works; stops at the last step | ✔ | ☐ |
| 10 | Step log | Open Step Log tab, click a row | Canvas and Trace jump to that step | ✔ | ☐ |
| 11 | Reset | Press Reset | Canvas returns to plain graph; Trace shows 0 / 0 | ✔ | ☐ |
| 12 | No path | Target = Legacy-Kiosk, Run to completion | "NO — no path exists"; 13 of 14 visited; final step says queue/stack empty | ✔ | ☐ |
| 13 | Source = target | Target = Laptop-HR | One-node path, 0 hops | ✔ | ☐ |
| 14 | Missing input | Network Editor → Clear all devices → Run → Generate Steps | Error dialog: network is empty | ✔ | ☐ |
| 15 | Editor: add | Add device "IoT-Camera"; connect it to Firewall-Int | Node appears in free space; dropdowns updated; E increases | ✔ | ☐ |
| 16 | Editor: reject | Connect the same pair again; connect a device to itself; add "iot-camera" | Each shows an error dialog; graph unchanged | ✔ | ☐ |
| 17 | Editor: remove | Remove a device / Disconnect a pair | Device and its edges disappear; traversal resets | ✔ | ☐ |
| 18 | Drag | Drag a device on the canvas | Device follows the mouse; edges follow | ✔ (synthetic mouse events) | ☐ |
| 19 | Resize | Maximise, then shrink to minimum size | Canvas rescales; nodes shrink; legend wraps; panels scroll | ✔ | ☐ |
| 20 | Concepts | Open Concepts tab and scroll | BFS/DFS explanation and O(V + E) / O(V) analysis readable | ✔ | ☐ |
| 21 | High-DPI | (If your laptop uses 125–150 % scaling) | Text is crisp and nothing is clipped | ☐ | ☐ |
