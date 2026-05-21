"""
Real-Time Network Sniffer
Built with Python | CodeAlpha Internship
Tech Stack: Python · Scapy · Tkinter · Threading
"""

import threading
import tkinter as tk
from tkinter import ttk, scrolledtext
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
except ImportError:
    print("Scapy not found. Install it with: pip install scapy")
    exit()


# ─────────────────────────────────────────────
#  Core sniffer logic (runs in background thread)
# ─────────────────────────────────────────────

class NetworkSniffer:
    def __init__(self, callback):
        """
        callback: function called with a packet-info dict
                  whenever a packet is captured
        """
        self.callback = callback
        self._stop_event = threading.Event()
        self._thread = None

    def _process_packet(self, packet):
        if self._stop_event.is_set():
            return

        if not packet.haslayer(IP):
            return

        ip_layer = packet[IP]
        info = {
            "time":     datetime.now().strftime("%H:%M:%S"),
            "src_ip":   ip_layer.src,
            "dst_ip":   ip_layer.dst,
            "protocol": "OTHER",
            "src_port": "-",
            "dst_port": "-",
            "length":   len(packet),
            "info":     "",
        }

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            info["protocol"] = "TCP"
            info["src_port"] = str(tcp.sport)
            info["dst_port"] = str(tcp.dport)
            flags = []
            if tcp.flags & 0x02: flags.append("SYN")
            if tcp.flags & 0x10: flags.append("ACK")
            if tcp.flags & 0x01: flags.append("FIN")
            if tcp.flags & 0x04: flags.append("RST")
            if tcp.flags & 0x08: flags.append("PSH")
            info["info"] = " ".join(flags) if flags else ""

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            info["protocol"] = "UDP"
            info["src_port"] = str(udp.sport)
            info["dst_port"] = str(udp.dport)
            info["info"] = f"Len={udp.len}"

        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            info["protocol"] = "ICMP"
            type_map = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable"}
            info["info"] = type_map.get(icmp.type, f"Type={icmp.type}")

        self.callback(info)

    def start(self, iface=None, packet_filter="ip"):
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=sniff,
            kwargs={
                "prn":    self._process_packet,
                "filter": packet_filter,
                "iface":  iface,
                "store":  False,
                "stop_filter": lambda _: self._stop_event.is_set(),
            },
            daemon=True,
        )
        self._thread.start()

    def stop(self):
        self._stop_event.set()


# ─────────────────────────────────────────────
#  Tkinter GUI
# ─────────────────────────────────────────────

PROTO_COLORS = {
    "TCP":   "#4fc3f7",   # light blue
    "UDP":   "#81c784",   # light green
    "ICMP":  "#ffb74d",   # orange
    "OTHER": "#ce93d8",   # purple
}

class SnifferApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Real-Time Network Sniffer — CodeAlpha")
        self.geometry("1100x680")
        self.configure(bg="#1e1e2e")
        self.resizable(True, True)

        self.sniffer = NetworkSniffer(callback=self._on_packet)
        self.packet_count = 0
        self.running = False
        self._queue = []
        self._lock = threading.Lock()

        self._build_ui()
        self._poll_queue()   # start polling every 100 ms

    # ── UI construction ──────────────────────

    def _build_ui(self):
        # ── Top bar ──
        top = tk.Frame(self, bg="#181825", pady=8)
        top.pack(fill="x")

        tk.Label(top, text="🛰  Network Sniffer",
                 font=("Consolas", 16, "bold"),
                 fg="#cdd6f4", bg="#181825").pack(side="left", padx=16)

        # Filter entry
        tk.Label(top, text="Filter:", fg="#a6adc8", bg="#181825",
                 font=("Consolas", 10)).pack(side="left", padx=(20, 4))
        self.filter_var = tk.StringVar(value="ip")
        tk.Entry(top, textvariable=self.filter_var, width=18,
                 bg="#313244", fg="#cdd6f4", insertbackground="white",
                 relief="flat", font=("Consolas", 10)).pack(side="left")

        # Buttons
        self.btn_start = tk.Button(top, text="▶  Start",
                                   command=self._start_sniffing,
                                   bg="#a6e3a1", fg="#1e1e2e",
                                   font=("Consolas", 10, "bold"),
                                   relief="flat", padx=10, pady=4,
                                   cursor="hand2")
        self.btn_start.pack(side="left", padx=12)

        self.btn_stop = tk.Button(top, text="■  Stop",
                                  command=self._stop_sniffing,
                                  bg="#f38ba8", fg="#1e1e2e",
                                  font=("Consolas", 10, "bold"),
                                  relief="flat", padx=10, pady=4,
                                  cursor="hand2", state="disabled")
        self.btn_stop.pack(side="left")

        tk.Button(top, text="🗑  Clear",
                  command=self._clear,
                  bg="#585b70", fg="#cdd6f4",
                  font=("Consolas", 10),
                  relief="flat", padx=10, pady=4,
                  cursor="hand2").pack(side="left", padx=12)

        # Status label (right side)
        self.status_var = tk.StringVar(value="Status: Idle")
        tk.Label(top, textvariable=self.status_var,
                 fg="#a6adc8", bg="#181825",
                 font=("Consolas", 10)).pack(side="right", padx=16)

        # ── Packet table ──
        cols = ("Time", "Protocol", "Src IP", "Src Port",
                "Dst IP", "Dst Port", "Length", "Info")

        frame = tk.Frame(self, bg="#1e1e2e")
        frame.pack(fill="both", expand=True, padx=10, pady=(6, 0))

        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("Sniffer.Treeview",
                         background="#1e1e2e",
                         foreground="#cdd6f4",
                         fieldbackground="#1e1e2e",
                         rowheight=22,
                         font=("Consolas", 9))
        style.configure("Sniffer.Treeview.Heading",
                         background="#313244",
                         foreground="#cdd6f4",
                         font=("Consolas", 9, "bold"),
                         relief="flat")
        style.map("Sniffer.Treeview",
                  background=[("selected", "#45475a")])

        self.tree = ttk.Treeview(frame, columns=cols, show="headings",
                                  style="Sniffer.Treeview")

        col_widths = [70, 70, 140, 75, 140, 75, 65, 250]
        for col, w in zip(cols, col_widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor="center" if w < 140 else "w")

        vsb = ttk.Scrollbar(frame, orient="vertical",   command=self.tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        # Tag colours per protocol
        for proto, color in PROTO_COLORS.items():
            self.tree.tag_configure(proto, foreground=color)

        # ── Detail / log panel ──
        self.log = scrolledtext.ScrolledText(
            self, height=8, bg="#181825", fg="#a6adc8",
            font=("Consolas", 9), relief="flat",
            insertbackground="white", state="disabled")
        self.log.pack(fill="x", padx=10, pady=6)

        # ── Bottom stats bar ──
        bot = tk.Frame(self, bg="#181825", pady=4)
        bot.pack(fill="x")
        self.count_var = tk.StringVar(value="Packets captured: 0")
        tk.Label(bot, textvariable=self.count_var,
                 fg="#a6adc8", bg="#181825",
                 font=("Consolas", 9)).pack(side="left", padx=16)
        tk.Label(bot, text="CodeAlpha Internship Project  |  github.com/syedMuhammadShaharyar",
                 fg="#585b70", bg="#181825",
                 font=("Consolas", 8)).pack(side="right", padx=16)

    # ── Button handlers ──────────────────────

    def _start_sniffing(self):
        pkt_filter = self.filter_var.get().strip() or "ip"
        self.sniffer.start(packet_filter=pkt_filter)
        self.running = True
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.status_var.set("Status: 🟢 Sniffing…")
        self._log(f"[{datetime.now().strftime('%H:%M:%S')}] Sniffing started  |  filter='{pkt_filter}'\n")

    def _stop_sniffing(self):
        self.sniffer.stop()
        self.running = False
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.status_var.set("Status: ⏹ Stopped")
        self._log(f"[{datetime.now().strftime('%H:%M:%S')}] Sniffing stopped  |  total={self.packet_count} packets\n")

    def _clear(self):
        self.tree.delete(*self.tree.get_children())
        self.packet_count = 0
        self.count_var.set("Packets captured: 0")
        self.log.config(state="normal")
        self.log.delete("1.0", "end")
        self.log.config(state="disabled")

    # ── Packet queue (thread-safe UI update) ─

    def _on_packet(self, info):
        """Called from sniffer thread — just enqueue, never touch Tk here."""
        with self._lock:
            self._queue.append(info)

    def _poll_queue(self):
        """Called from main thread every 100 ms to drain the queue."""
        with self._lock:
            batch = self._queue[:]
            self._queue.clear()

        for info in batch:
            self._insert_row(info)

        self.after(100, self._poll_queue)

    def _insert_row(self, info):
        proto = info["protocol"]
        values = (
            info["time"],
            proto,
            info["src_ip"],
            info["src_port"],
            info["dst_ip"],
            info["dst_port"],
            info["length"],
            info["info"],
        )
        self.tree.insert("", "end", values=values, tags=(proto,))
        # Auto-scroll to latest
        children = self.tree.get_children()
        if children:
            self.tree.see(children[-1])

        self.packet_count += 1
        self.count_var.set(f"Packets captured: {self.packet_count}")

    # ── Log panel ────────────────────────────

    def _log(self, msg):
        self.log.config(state="normal")
        self.log.insert("end", msg)
        self.log.see("end")
        self.log.config(state="disabled")

    # ── Clean shutdown ────────────────────────

    def on_close(self):
        if self.running:
            self.sniffer.stop()
        self.destroy()


# ─────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    app = SnifferApp()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
