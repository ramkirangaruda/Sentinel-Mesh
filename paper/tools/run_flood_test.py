#!/usr/bin/env python3
"""One-command bench run: baseline -> DEFENSE <mode> -> flood -> recovery.

All three boards stay plugged into the laptop (G, F, A each on its own COM
port). The script logs every board to its own file and sends the control lines
itself, so nobody types into a monitor or moves a board to a charger.

  python paper/tools/run_flood_test.py --g COM6 --f COM8 --a COM7 --defence gate

Close every `pio device monitor` first: only one program can hold a COM port.
Needs pyserial (already installed with PlatformIO in the venv).
A must be flashed with the plain `attacker` env (starts OFF); this script
sends `MODE FLOOD`, so the boot-mode envs are not needed.
Output: paper/data/E_phase6/runs/<stamp>_<defence>_{G,F,A}.log plus a
timeline file with the exact times each command was sent.
"""
import argparse, os, sys, threading, time
from datetime import datetime
import serial

def open_port(name, baud):
    s = serial.Serial()
    s.port, s.baudrate, s.timeout = name, baud, 0.2
    s.dtr = False          # keep the ESP32 from resetting on open
    s.rts = False
    s.open()
    return s

class Logger(threading.Thread):
    def __init__(self, label, ser, path, t0):
        super().__init__(daemon=True)
        self.label, self.ser, self.t0, self.stop = label, ser, t0, False
        self.f = open(path, "w", encoding="utf-8", newline="\n")
    def run(self):
        buf = b""
        while not self.stop:
            try:
                buf += self.ser.read(512)
            except Exception as e:
                self.f.write(f"[{time.time()-self.t0:8.2f}s] <serial error {e}>\n"); break
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                self.f.write(f"[{time.time()-self.t0:8.2f}s] "
                             + line.decode("utf-8", "replace").rstrip("\r") + "\n")
            self.f.flush()
        self.f.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--g", required=True, help="gateway port, e.g. COM6")
    ap.add_argument("--f", required=True, help="field-node port")
    ap.add_argument("--a", required=True, help="attacker port")
    ap.add_argument("--defence", default="gate", help="none|ratelimit|cookie|gate")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--baseline", type=int, default=60, help="s before DEFENSE is set")
    ap.add_argument("--settle", type=int, default=30, help="s between DEFENSE and flood")
    ap.add_argument("--flood", type=int, default=120)
    ap.add_argument("--recovery", type=int, default=60)
    ap.add_argument("--attack", default="FLOOD", help="FLOOD|INSIDER|SLOW_DRIP|...")
    ap.add_argument("--out", default=os.path.join("paper", "data", "E_phase6", "runs"))
    a = ap.parse_args()

    os.makedirs(a.out, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.join(a.out, f"{stamp}_{a.defence}_{a.attack.lower()}")
    t0 = time.time()
    ports = {"G": a.g, "F": a.f, "A": a.a}
    sers, logs = {}, []
    for k, p in ports.items():
        sers[k] = open_port(p, a.baud)
        lg = Logger(k, sers[k], f"{base}_{k}.log", t0); lg.start(); logs.append(lg)
    tl = open(f"{base}_timeline.txt", "w")
    def send(k, line):
        sers[k].write((line + "\n").encode()); sers[k].flush()
        msg = f"[{time.time()-t0:8.2f}s] {datetime.now():%H:%M:%S} -> {k}: {line}"
        print(msg); tl.write(msg + "\n"); tl.flush()
    def wait(s, why):
        print(f"   waiting {s}s ({why})")
        time.sleep(s)

    try:
        send("A", "MODE OFF"); send("G", "DEFENSE none")
        wait(a.baseline, "baseline, defence none, no attack")
        send("G", f"DEFENSE {a.defence}")
        wait(a.settle, "defence settling, no attack")
        send("A", f"MODE {a.attack}")
        wait(a.flood, f"attack {a.attack}")
        send("A", "STATS")
        time.sleep(1)
        send("A", "MODE OFF")
        wait(a.recovery, "recovery, no attack")
        send("G", "DEFENSE none")
        time.sleep(2)
    finally:
        for lg in logs: lg.stop = True
        time.sleep(0.5)
        for s in sers.values(): s.close()
        tl.close()
    print("\nDone. Logs:")
    for k in ports: print(f"  {base}_{k}.log")
    print(f"  {base}_timeline.txt")

if __name__ == "__main__":
    sys.exit(main())
