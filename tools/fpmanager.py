#!/usr/local/bin/python3
"""FP Manager — gestione impronte ControlVault, stile Touch ID di macOS.

Aggiungi / rinomina / rimuovi / verifica le impronte usate per sudo e sblocco schermo.
Dati in ~/usbcfg/controlvault/mac_template.json.

Avvio:  /usr/local/bin/python3 ~/usbcfg/tools/fpmanager.py
"""
import sys, os, json, time, math, threading, queue

TOOLS = "/Users/amoslobianco/usbcfg/tools"
CV = "/Users/amoslobianco/usbcfg/controlvault"
sys.path.insert(0, TOOLS); sys.path.insert(0, CV)

import tkinter as tk
from tkinter import simpledialog, messagebox

TPL = os.path.join(CV, "mac_template.json")

# --- palette stile Touch ID ---
BG = "#f2f2f7"
CARD = "#ffffff"
INK = "#1d1d1f"
SUB = "#8a8a8e"
PINK = "#ff2d55"        # glifo impronta attivo
PINK_SOFT = "#ffd4dd"   # archi non ancora riempiti
LINE = "#d9d9de"
SEL = "#0a84ff"
NCOLS = 4
TILE_W, TILE_H = 132, 150
STAGES = 8   # tocchi richiesti per registrare (piu' alto = template piu' robusto)


def load_templates():
    try:
        return json.load(open(TPL)).get("templates", [])
    except Exception:
        return []


def save_templates(items):
    json.dump({"templates": items}, open(TPL, "w"), indent=2)


# archi del glifo impronta (frazione raggio, start, extent) — dome stile touchid
ARCS = [(1.00, 20, 140), (0.74, 8, 164), (0.50, 18, 150), (0.28, 30, 120)]


def draw_fingerprint(cv, cx, cy, R, filled=99, active=PINK, inactive=PINK_SOFT, w=5):
    """Disegna il glifo impronta; 'filled' = quanti archi (dal basso) sono attivi."""
    n = len(ARCS)
    for i, (rf, start, extent) in enumerate(ARCS):
        r = R * rf
        col = active if (n - i) <= filled else inactive
        cv.create_arc(cx - r, cy - r, cx + r, cy + r, start=start, extent=extent,
                      style=tk.ARC, outline=col, width=w)
    # puntino centrale
    col = active if filled >= 1 else inactive
    cv.create_oval(cx - w, cy - w, cx + w, cy + w, fill=col, outline=col)


def round_rect(cv, x1, y1, x2, y2, r, **kw):
    pts = [x1+r,y1, x2-r,y1, x2,y1, x2,y1+r, x2,y2-r, x2,y2, x2-r,y2,
           x1+r,y2, x1,y2, x1,y2-r, x1,y1+r, x1,y1]
    return cv.create_polygon(pts, smooth=True, **kw)


class App:
    def __init__(self, root):
        self.root = root
        self.q = queue.Queue()
        self.busy = False
        self.enroll_dlg = None
        root.title("FP Manager")
        root.configure(bg=BG)
        root.geometry("600x520"); root.minsize(520, 460)

        wrap = tk.Frame(root, bg=BG)
        wrap.pack(fill="both", expand=True, padx=26, pady=22)

        tk.Label(wrap, text="Touch ID", bg=BG, fg=INK,
                 font=("SF Pro Display", 22, "bold")).pack(anchor="w")
        tk.Label(wrap, text="Un'impronta può sbloccare il Mac e autorizzare sudo.",
                 bg=BG, fg=SUB, font=("SF Pro Text", 12)).pack(anchor="w", pady=(2, 16))

        self.grid = tk.Frame(wrap, bg=BG)
        self.grid.pack(fill="both", expand=True)

        bar = tk.Frame(wrap, bg=BG); bar.pack(fill="x", pady=(14, 0))
        self.status = tk.Label(bar, text="", bg=BG, fg=SUB, font=("SF Pro Text", 11))
        self.status.pack(side="left")
        self.verify_btn = tk.Label(bar, text="✔ Verifica dito", bg=BG, fg=SEL,
                                   font=("SF Pro Text", 12), cursor="pointinghand")
        self.verify_btn.pack(side="right")
        self.verify_btn.bind("<Button-1>", lambda e: self.on_verify())

        self.render()
        self.root.after(80, self._pump)

    # ---------- rendering tessere ----------
    def render(self):
        for w in self.grid.winfo_children():
            w.destroy()
        items = load_templates()
        for idx, t in enumerate(items):
            self._tile(idx, t).grid(row=idx // NCOLS, column=idx % NCOLS, padx=10, pady=10)
        add_i = len(items)
        self._add_tile().grid(row=add_i // NCOLS, column=add_i % NCOLS, padx=10, pady=10)

    def _tile(self, idx, t):
        c = tk.Canvas(self.grid, width=TILE_W, height=TILE_H, bg=BG,
                      highlightthickness=0, cursor="pointinghand")
        round_rect(c, 6, 6, TILE_W-6, TILE_H-34, 22, fill=CARD, outline=LINE)
        draw_fingerprint(c, TILE_W/2, (TILE_H-34)/2 + 8, 34, filled=99, w=5)
        name = t.get("name") or "Impronta %d" % (idx + 1)
        c.create_text(TILE_W/2, TILE_H-14, text=name, fill=INK, font=("SF Pro Text", 12))
        # × elimina (appare al passaggio del mouse)
        x0, y0 = 16, 16
        xb = c.create_oval(x0-10, y0-10, x0+10, y0+10, fill="#ff3b30", outline="", state="hidden")
        xt = c.create_text(x0, y0, text="×", fill="white", font=("SF Pro Text", 13, "bold"), state="hidden")
        def show(_=None):
            c.itemconfigure(xb, state="normal"); c.itemconfigure(xt, state="normal")
        def hide(_=None):
            c.itemconfigure(xb, state="hidden"); c.itemconfigure(xt, state="hidden")
        c.bind("<Enter>", show); c.bind("<Leave>", hide)
        def click(ev):
            if (ev.x-x0)**2 + (ev.y-y0)**2 <= 150:
                self.remove(idx)
            elif ev.y > TILE_H-30:
                self.rename(idx)
        c.bind("<Button-1>", click)
        c.bind("<Double-Button-1>", lambda e: self.rename(idx))
        return c

    def _add_tile(self):
        c = tk.Canvas(self.grid, width=TILE_W, height=TILE_H, bg=BG,
                      highlightthickness=0, cursor="pointinghand")
        round_rect(c, 6, 6, TILE_W-6, TILE_H-34, 22, fill=BG, outline=SUB)
        # tratteggio simulato: bordo grigio + glifo tenue
        draw_fingerprint(c, TILE_W/2, (TILE_H-34)/2 + 8, 34, filled=0,
                         inactive="#c7c7cc", w=5)
        c.create_text(TILE_W/2, (TILE_H-34)/2 + 8, text="+", fill=SUB, font=("SF Pro Text", 20, "bold"))
        c.create_text(TILE_W/2, TILE_H-14, text="Aggiungi impronta", fill=SEL, font=("SF Pro Text", 12))
        c.bind("<Button-1>", lambda e: self.on_add())
        return c

    # ---------- coda / UI thread-safe ----------
    def emit(self, m): self.q.put(("log", m))
    def set_status(self, m, c=SUB): self.q.put(("status", (m, c)))

    def _pump(self):
        try:
            while True:
                kind, p = self.q.get_nowait()
                if kind == "status":
                    self.status.configure(text=p[0], fg=p[1])
                elif kind == "enroll_event" and self.enroll_dlg:
                    self.enroll_dlg.on_event(p)
                elif kind == "enroll_done":
                    if self.enroll_dlg:
                        self.enroll_dlg.finish(p)
                    self._set_busy(False); self.render()
                elif kind == "done":
                    self._set_busy(False); self.render()
        except queue.Empty:
            pass
        self.root.after(80, self._pump)

    def _set_busy(self, b): self.busy = b

    # ---------- azioni ----------
    def on_add(self):
        if self.busy:
            return
        name = simpledialog.askstring("Nuova impronta", "Nome (es. 'Indice destro'):", parent=self.root)
        if name is None:
            return
        name = name.strip() or "Impronta"
        self._set_busy(True)
        self.enroll_dlg = EnrollDialog(self.root, name)
        threading.Thread(target=self._do_enroll, args=(name,), daemon=True).start()

    def _do_enroll(self, name):
        try:
            import controlvault as C
            import secure
            d = C.ControlVault(); d.claim()
            try:
                s = secure.SecureSession(d); s.reset(); s.handshake()
                ok, last, stages, cst, handle, tid = s.enroll(
                    target_stages=STAGES, max_stages=STAGES + 6,
                    on_event=lambda m: self.q.put(("enroll_event", m)))
                if ok and handle:
                    items = [x for x in load_templates() if x.get("handle") != handle]
                    items.append({"name": name, "handle": handle, "id": tid.hex(),
                                  "ts": time.strftime("%Y-%m-%d %H:%M:%S")})
                    save_templates(items)
                    self.q.put(("enroll_done", (True, "")))
                else:
                    self.q.put(("enroll_done", (False, "Registrazione fallita (0x%x)" % last)))
            finally:
                d.release()
        except Exception as e:
            self.q.put(("enroll_done", (False, "Errore: %s" % e)))

    def rename(self, idx):
        items = load_templates()
        if idx >= len(items):
            return
        cur = items[idx].get("name", "")
        name = simpledialog.askstring("Rinomina", "Nuovo nome:", initialvalue=cur, parent=self.root)
        if name is None:
            return
        items[idx]["name"] = name.strip() or cur
        save_templates(items); self.render()

    def remove(self, idx):
        if self.busy:
            return
        items = load_templates()
        if idx >= len(items):
            return
        t = items[idx]
        name = t.get("name") or "questa impronta"
        handle = t.get("handle")
        if not messagebox.askyesno("Rimuovi impronta",
                "Rimuovere '%s'?\nVerrà cancellata dal lettore e non sarà più usata." % name):
            return
        self._set_busy(True); self.set_status("Rimozione dal chip…", "#ef6c00")
        threading.Thread(target=self._do_remove, args=(handle, name), daemon=True).start()

    def _do_remove(self, handle, name):
        chip_ok = None
        try:
            if handle:
                import controlvault as C
                import secure
                d = C.ControlVault(); d.claim()
                try:
                    s = secure.SecureSession(d); s.reset(); s.handshake()
                    st, ih = s.open72()
                    if st == 0:
                        st2, _ = s.delete_object(handle)
                        chip_ok = (st2 == 0)
                    else:
                        chip_ok = False
                finally:
                    d.release()
        except Exception:
            chip_ok = False
        # scollega comunque dal JSON (non più usata per sudo/sblocco)
        save_templates([x for x in load_templates() if x.get("handle") != handle])
        if chip_ok:
            self.set_status("✅ '%s' cancellata dal chip" % name, "#2e7d32")
        elif handle:
            self.set_status("'%s' scollegata (chip non confermato)" % name, "#ef6c00")
        else:
            self.set_status("'%s' rimossa" % name, SUB)
        self.q.put(("done", None))

    def on_verify(self):
        if self.busy or not load_templates():
            if not load_templates():
                messagebox.showinfo("Verifica", "Nessuna impronta registrata.")
            return
        self._set_busy(True); self.set_status("Appoggia il dito…", "#ef6c00")
        threading.Thread(target=self._do_verify, daemon=True).start()

    def _do_verify(self):
        try:
            import controlvault as C
            import secure
            handles = [t["handle"] for t in load_templates() if t.get("handle")]
            d = C.ControlVault(); d.claim()
            try:
                s = secure.SecureSession(d); s.reset(); s.handshake()
                st, ih = s.open()
                if st != 0:
                    self.set_status("Lettore non pronto", "#c62828"); return
                stc, R, pl, notif = s.capture()
                if stc != 0:
                    for cw in (0x0440006d, 0x04400068):
                        try: d.transact(C.build_envelope(cw, bytes.fromhex("000000000400000000000000"), counter=2))
                        except Exception: pass
                    stc, R, pl, notif = s.capture()
                if stc != 0 or not s.wait_finger(to=15000):
                    self.set_status("Nessun dito", "#c62828"); return
                res = 0
                for _ in range(10):
                    st2, res, mid, mh = s.verify(handles)
                    if st2 not in (0x85, 0x0f): break
                    time.sleep(0.2)
                self.set_status("✅ Riconosciuta" if res == 1 else "❌ Non riconosciuta",
                                "#2e7d32" if res == 1 else "#c62828")
            finally:
                d.release()
        except Exception as e:
            self.set_status("Errore: %s" % e, "#c62828")
        finally:
            self.q.put(("done", None))


class EnrollDialog(tk.Toplevel):
    """Finestra stile Touch ID: impronta grande che si riempie a ogni tocco."""
    def __init__(self, parent, name):
        super().__init__(parent)
        self.configure(bg=CARD)
        self.title("Aggiungi impronta")
        self.geometry("360x380"); self.resizable(False, False)
        self.transient(parent); self.grab_set()
        self.stages = 0
        tk.Label(self, text="Appoggia e solleva il dito", bg=CARD, fg=INK,
                 font=("SF Pro Display", 16, "bold")).pack(pady=(26, 4))
        tk.Label(self, text="«%s»" % name, bg=CARD, fg=SUB, font=("SF Pro Text", 12)).pack()
        self.cv = tk.Canvas(self, width=220, height=220, bg=CARD, highlightthickness=0)
        self.cv.pack(pady=18)
        self.msg = tk.Label(self, text="Solleva e riappoggia più volte…", bg=CARD, fg=SUB,
                            font=("SF Pro Text", 12))
        self.msg.pack()
        self.redraw()

    def redraw(self):
        self.cv.delete("all")
        draw_fingerprint(self.cv, 110, 110, 86,
                         filled=self.stages * (len(ARCS) / float(STAGES)) if self.stages else 0, w=9)
        self.cv.create_text(110, 205, text="%d / %d" % (self.stages, STAGES), fill=SUB,
                            font=("SF Pro Text", 12))

    def on_event(self, m):
        if "STAGE OK" in m:
            self.stages = min(STAGES, self.stages + 1)
            self.redraw()
            self.msg.configure(text="Bene! Solleva e riappoggia il dito…")
        elif ">> APPOGGIA" in m or "APPOGGIA" in m:
            self.msg.configure(text="Appoggia il dito sul sensore")
        elif "COMMIT" in m:
            self.msg.configure(text="Completamento…")

    def finish(self, result):
        ok, err = result
        if ok:
            self.stages = STAGES; self.redraw()
            self.msg.configure(text="✅ Impronta registrata", fg="#2e7d32")
            self.after(900, self.destroy)
        else:
            self.msg.configure(text=err or "Fallita", fg="#c62828")
            self.after(1600, self.destroy)


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
