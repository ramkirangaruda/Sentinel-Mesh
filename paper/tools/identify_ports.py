#!/usr/bin/env python3
"""Tell which COM port is which board: reset each one and read its boot output.

  python paper/tools/identify_ports.py            # all ports pyserial can see
  python paper/tools/identify_ports.py COM6 COM7  # just these

Close every `pio device monitor` first. Each board is reset (RTS pulse) and
listened to for about 5 s; the role is guessed from the keywords in what the
firmware prints. A blank board or one running other firmware shows as UNKNOWN.
"""
import re, sys, time
import serial
from serial.tools import list_ports

def read_boot(port, secs=5.0):
    s = serial.Serial()
    s.port, s.baudrate, s.timeout = port, 115200, 0.2
    s.dtr = False
    s.rts = False
    s.open()
    time.sleep(0.1)
    s.rts = True          # EN low = reset
    time.sleep(0.15)
    s.rts = False
    out, end = b"", time.time() + secs
    while time.time() < end:
        out += s.read(512)
    s.close()
    return out.decode("utf-8", "replace")

def guess(text):
    t = text.lower()
    for key, name in (("attacker boot", "A  (attacker)"), ("gateway boot", "G  (gateway)"),
                      ("field_node boot", "F  (field node)"), ("monitor boot", "M  (monitor)")):
        if key in t: return name
    if "attacker" in t: return "A  (attacker)"
    if "gateway" in t or "gw stats" in t or "defence mode" in t and "relayed" in t: return "G  (gateway)"
    if "field" in t or "gate spend" in t or "session established" in t or "stats spend=" in t: return "F  (field node)"
    if "ina219" in t or "monitor" in t: return "M  (monitor)"
    return "UNKNOWN"

def main():
    # boot garbage bytes crash a cp1252 Windows console without this
    sys.stdout.reconfigure(errors="replace")
    # USB serial only (vid set): skips Bluetooth COM ports, which hang or waste 5 s each
    usb = [p for p in list_ports.comports() if p.vid is not None]
    ports = sys.argv[1:] or [p.device for p in sorted(usb, key=lambda p: int(re.sub(r"\D", "", p.device) or 0))]
    if not ports:
        print("no USB serial ports found: check the cables (charge-only cables give power but no data)")
    for p in ports:
        try:
            txt = read_boot(p)
        except Exception as e:
            print(f"{p}: could not open ({e}). Is a monitor still open?"); continue
        lines = [l.strip() for l in txt.splitlines() if l.strip()]
        mac = re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", txt)
        print(f"\n{p}: {guess(txt)}" + (f"   MAC {mac.group(1)}" if mac else ""))
        for l in lines[:6]: print("    " + l[:140])
        if not lines: print("    (no output: blank board, or wrong baud/cable)")

if __name__ == "__main__":
    main()
