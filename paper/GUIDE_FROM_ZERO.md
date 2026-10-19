# SentinelMesh from zero: the project, the electronics, and every step to the paper

Written 2026-10-18 for team members who have never done hardware. Read it top to bottom once. After that, use
section 9 (the step list) as your checklist. Facts come from the repo (`paper/HANDOFF_3DAY.md`,
`paper/decisions.md`, `docs/hardware_setup.md`) and from Ramkiran's chat with Claude (2026-10-08 to 10-14).

Contents
1. The project in plain words
2. The research paper: what we are trying to prove
3. The ideas behind it, explained simply
4. Electricity basics you need (and nothing more)
5. Every part on the table, what it is and how to hold it
6. The four boards: F, G, A, M
7. Software on the laptop
8. Safety rules (read twice)
9. The step-by-step plan (Day 0 to Day 3)
10. When something goes wrong
11. Glossary

---

## 1. The project in plain words

In December 2015 attackers switched off power for about 230,000 people in Ukraine. They did it in stages: a
phishing email, a malicious attachment, movement through the power company's control network, then sending
commands to field equipment.

At the **Code Cortex 3.0** hackathon (Security track) our team, "One Last Run" (Navika Kapoor, Chaitanya
Patil, Adithya Binoj Nair, Ramkiran), built **SentinelMesh**, a detector for each stage of that attack:

| Layer | Name | What it does |
|---|---|---|
| Email | MailGuard | machine-learning model that scores emails for phishing |
| File | FileGuard | model that scores Windows programs for malware (from file features only, no live malware) |
| Field network | the ESP32 mesh | small radio boards that talk to each other securely and detect attacks on that radio network |
| Physical | TamperGuard | light sensor and switch that notice if a box is opened |

A web **console** joins all their alerts into one incident. We won 1st place.

The part we are turning into a research paper is the **field network**: small, battery-powered radio boards
(ESP32s) that talk using **post-quantum cryptography**, and a defence called **EnergyGate**.

## 2. The research paper: what we are trying to prove

**One-sentence thesis: post-quantum cryptography protects the message, but not the battery.**

What this means:
- Post-quantum crypto is the new kind of encryption designed to survive future quantum computers. It works, but
  it is **heavy**: big keys (several kilobytes) and a lot of computation.
- Before two boards can talk securely they do a **handshake** (they prove who they are and agree on a secret
  key). The board receiving a handshake must do expensive maths to check it.
- An attacker does not need to break the encryption. They can just **send fake handshakes over and over**. Each
  fake one makes the victim board do expensive maths and receive about 20 radio packets, which uses battery.
  The attacker spends very little; the victim spends a lot. Do it long enough and the battery dies. This is an
  **energy-exhaustion attack** (a kind of denial of service).
- **EnergyGate** is our defence. When a handshake starts arriving, it looks at cheap clues (how many handshakes
  per second, how many failed, signal strength, and so on), gives it a score, and checks how much energy is
  left in a "joule budget". Then it decides: **SPEND** (do the expensive check), **CHALLENGE** (ask the sender
  to prove it can hear us first, which costs us very little), or **DROP** (ignore it).

The paper's four claims:

| Claim | In plain words | Needs |
|---|---|---|
| **C1** | We measured how much energy a post-quantum handshake really costs on a real board, radio included | the energy rig (INA219) |
| **C2** | We measured how many joules the victim loses per joule the attacker spends, for each attack and defence | the rig plus the attack runs |
| **C3** | Our gate keeps the battery safe with a guaranteed upper limit, and still lets real nodes in | attack runs, repeated |
| **C4** | All code and data are open | the repo |

**What is already done:** the post-quantum crypto runs on the ESP32; the boards do real handshakes over the
radio; the attack and the gate work on the bench (but only measured on USB power, so **no energy numbers yet**).
**What is missing:** the energy measurements. That is what the hardware work below is for.

**Honesty rules for the paper** (these are not optional):
- Anything not measured on real hardware is labelled **SIMULATED**. Right now that includes: the battery level
  (fixed at 100%), the EnergyGate model (trained on simulated data), and the cost of a challenge (0.0005 J is a
  placeholder).
- Never edit a raw log. A bad run stays in the folder and is marked `excluded=y` in `paper/runlog.csv` with the
  reason.
- Each condition must be repeated (at least 5 times) before we claim anything about it.

## 3. The ideas behind it, explained simply

**ESP32.** A small, cheap computer on a board about the size of a finger (about Rs 400). It has Wi-Fi/radio
built in, many pins to connect sensors, and a USB port. We use the "ESP32-WROOM-32 DevKit" with a micro-USB
port.

**ESP-NOW.** A simple radio protocol between ESP32s, with no Wi-Fi router needed. One radio packet carries at
most about 250 bytes. A post-quantum handshake message is about 4,500 bytes, so it is cut into **fragments**:
a HELLO is 20 fragments and the reply is 19. All 39 must arrive or the handshake fails. ESP-NOW broadcast
does not resend lost packets, which is why handshakes sometimes time out when boards are far apart.

**The handshake** (3 messages):
1. Gateway → field node: **HELLO** (a fresh public key, signed to prove it is really the gateway).
2. Field node → gateway: **RESPONSE** (an encrypted secret for that key, signed by the field node).
3. Gateway → field node: **CONFIRM** (proof both now share the same secret).

The crypto names:
- **ML-KEM** (key exchange, formerly "Kyber"): makes the shared secret. Level 1 = ML-KEM-512, level 3 (our
  default) = ML-KEM-768.
- **ML-DSA** (signatures, formerly "Dilithium"): proves who sent a message. Level 3 = ML-DSA-65. **Verifying**
  a signature is the expensive step the attacker forces on the victim.
- **AES-256-GCM**: the fast normal encryption used after the handshake.

**Cookie / challenge.** Instead of checking a suspicious HELLO, the field node replies "send that again with this
8-byte cookie". A real gateway can hear the reply and resends with the cookie. A blind forger that cannot hear
cannot. Weakness: an attacker that listens can copy the cookie (our attacker's `ECHO on` mode). That is why the
**joule budget** is the real safety limit, not the cookie.

**Joule budget (token bucket).** The field node keeps an energy allowance, like pocket money: it refills slowly,
and every expensive check spends some. When it runs out, the node stops spending on unknown senders. This
guarantees a worst-case drain even if the attacker fools the score.

**Defence modes** you will type: `none` (check everything), `ratelimit` (only N per second), `cookie` (always
challenge first), `gate` (EnergyGate). Gate **v2** (the current default) challenges low scores instead of
dropping them; **v1** dropped them and in testing it also dropped the real gateway (0 of 10 got through).

**Attack modes** on the attacker board: `FLOOD` (many fake HELLOs per second), `INSIDER` (pretends to be the real
gateway), `SLOW_DRIP` (about one per minute, to stay under rate limits), `REPLAY`, `IMPERSONATE`, `WEAK_LINK`.

## 4. Electricity basics you need (and nothing more)

Think of electricity as water in pipes.

| Quantity | Water picture | Unit | Example here |
|---|---|---|---|
| **Voltage (V)** | water pressure | volt, V | the adaptor gives 5 V; the ESP32 chip runs at 3.3 V |
| **Current (I)** | how much water flows per second | ampere, A (1 mA = 0.001 A) | an ESP32 with radio on draws roughly 80-250 mA |
| **Resistance (R)** | how narrow the pipe is | ohm, Ω (1 kΩ = 1000 Ω) | our resistors: 39, 47, 56, 1000 Ω |
| **Power (P)** | how hard the water works right now | watt, W (mW = 0.001 W) | P = V × I |
| **Energy (E)** | total work done over time | joule, J (mJ = 0.001 J) | E = P × time. **This is what the paper measures.** |

**Ohm's law: V = I × R** (so I = V / R). Example: 5 V across 168 Ω gives I = 5 / 168 = 0.0298 A = 29.8 mA.

**Power in a resistor: P = V × V / R.** Our resistors are small "¼ W" parts: they safely turn at most 0.25 W into
heat. 5 V across 22 Ω is 5 × 5 / 22 = 1.14 W, more than four times too much: it gets very hot and can burn.
**That is why the old plan's 22 Ω and 10 Ω loads must not be used.** Our safe loads are in section 9.

**Series and parallel.**
- **Series** (one after another, like links in a chain): resistances add. 56 + 56 + 56 = 168 Ω. The voltage is
  shared between them, so each heats less.
- **Parallel** (side by side, like lanes on a road): current splits between them. Three equal 47 Ω strings in
  parallel = 47 / 3 ≈ 15.7 Ω total.

**Circuit.** Current only flows in a complete loop: out of the + side, through the thing, back into the − side
(GND). A wire straight from + to − with nothing in between is a **short circuit**: huge current, heat, damage.
Never let bare + and − wires touch.

**GND (ground)** is the common "zero volts" reference. **All boards that talk to each other or measure each
other must have their GNDs connected together.** Forgetting this is the most common reason readings are wrong.

**Polarity.** + and − matter. Reversing them on an ESP32 can kill it. Always check with the multimeter before
connecting.

**How the INA219 measures current.** Inside it is a tiny resistor (0.1 Ω) called a **shunt**. All the current
going to the board flows through it. Current through a resistor makes a tiny voltage across it (V = I × R, so
100 mA × 0.1 Ω = 10 mV). The INA219 measures that tiny voltage and works out the current, and also measures the
supply voltage. Current × voltage = power; add it up over time = energy. **If any current reaches the board by
another path (for example the USB cable's 5 V), the INA219 never sees it and the reading is wrong.**

## 5. Every part on the table, what it is and how to hold it

**ESP32 DevKit (×4, labelled F, G, A, M on the back).**
- Micro-USB port: power plus data to the laptop (through a CP2102 chip, which needs a Windows driver; Ram's
  laptop already has it).
- Two buttons: **EN** (reset, restarts the program) and **BOOT** (only needed if flashing gets stuck: hold BOOT,
  press EN, release BOOT).
- Pins along both edges, labelled on the board. The ones we use: **VIN** (5 V in), **GND**, **3V3** (3.3 V out),
  **D21** (GPIO21, I2C data), **D22** (GPIO22, I2C clock), **D4** (GPIO4, our "marker" pin).
- A red LED = the board has power. It does not mean the program is running.
- Never put more than about 5.5 V into VIN. Never connect anything to the 3V3 pin from outside.

**INA219 current sensor board (×2).** A small purple or blue board. Pins:
- **VCC** and **GND**: its own power (3.3 V from M).
- **SDA** and **SCL**: the I2C wires, so M can read it. I2C is a two-wire way for chips to talk.
- **Vin+** and **Vin−** (often a 2-screw green terminal as well as pins): the current to be measured goes **in at
  Vin+ and out at Vin−**.
- It arrives with loose pin headers that must be **soldered** on. Ram planned to do this on 2026-10-15. **Check
  the solder joints before use** (section 9, step 1.2).

**Multimeter.** Measures voltage, resistance and continuity. Black probe always in the **COM** socket; red in the
**VΩ** socket. (Never put the red probe in the **A** or **mA** socket for this project: that turns the meter into
a short circuit if you then touch it across a supply.) The dial modes we use:
- **DC V (V⎓, 20 V range)**: voltage. Touch the two probes on the two points. Works with power on.
- **Ω (resistance)**: only with power **off**. Touch the two ends of the resistor.
- **Continuity (diode/speaker symbol)**: beeps if two points are connected. Power off. Used to find solder
  bridges.

**Breadboard.** A plastic board with holes. Inside, the holes are joined in groups: each short row of 5 holes is
one connection (the two halves of the board are separate). The long lines on the edges marked + and − are
connected along their whole length. Push a wire and a resistor leg into the same 5-hole row and they are
connected.

**Jumper wires.** Male end = pin, female end = socket. Male-to-female goes from a breadboard to a board pin.

**Resistors.** Colour bands give the value, but reading them from photos is unreliable. **Always measure with the
multimeter (Ω mode).** Our stock (2026-10-19): a ROBOLARK ¼ W 5 % carbon-film kit, 30 values × 5 each (10 Ω to
1 MΩ). Rule: a single ¼ W resistor across 5 V must be **220 Ω or more**; never put 10-150 Ω alone across 5 V.

**5 V 2 A barrel-plug adaptor (Ve-Pro).** Plugs into the wall; the round plug has a centre pin (should be +) and
an outer sleeve (−). To use it we need either a **barrel-jack-to-screw-terminal adapter** (a small plug-in socket
with two screws marked + and −; cheap; preferred) or to cut the cable and strip the two wires.

**Not yet bought:** the screw-terminal adapter (if not already), and a battery for the run-down test (optional;
see section 9, decisions).

## 6. The four boards: F, G, A, M

| Label | Role | MAC address (its unique ID) | Firmware (program) on it |
|---|---|---|---|
| **F** | **Field node**, the victim. Runs EnergyGate. This is the board we measure. | A4:F0:0F:77:A2:70 | `field_node_bench` now; `field_node_energy` for energy runs |
| **G** | **Gateway**, the legitimate partner that does handshakes with F every few seconds | 5C:01:3B:BE:A0:10 | `gateway` |
| **A** | **Attacker**, sends fake HELLOs at F | 8C:94:DF:58:DA:1C | `attacker` (starts OFF; the scripts switch its mode) |
| **M** | **Monitor**, reads the INA219 and prints energy numbers | 30:76:F5:05:3E:A0 | `monitor_ina219` |

**COM ports.** When a board is plugged into Windows by USB it gets a name like COM6. The number changes when you
move a cable. Never trust an old number: run `identify_ports.py` (section 7) every session.

## 7. Software on the laptop

You type commands in **PowerShell** (Start menu → "PowerShell"), or the terminal inside VS Code.

**One-time setup (about 10 minutes, needs internet):**
1. Get the code: `git clone https://github.com/ramkirangaruda/Sentinel-Mesh.git` (or `git pull` inside an
   existing copy). Then `git checkout paper/e5-grid-tooling` (our working branch).
2. Make a Python "virtual environment" (a private box of tools) **outside the repo** so git ignores it:
   ```
   python -m venv $HOME\sentinel-venv
   ```
3. Turn it on: `& $HOME\sentinel-venv\Scripts\Activate.ps1`. The prompt now starts with `(sentinel-venv)`. Do this
   every time you open a new terminal. (If Windows says scripts are disabled, skip activation and type
   `$HOME\sentinel-venv\Scripts\pio.exe` instead of `pio`, and `$HOME\sentinel-venv\Scripts\python.exe` instead of
   `python`.)
4. Install PlatformIO (the tool that compiles and uploads ESP32 programs) and pyserial (lets Python talk to COM
   ports): `pip install platformio pyserial`.
5. If a board does not show up as a COM port at all, install the **CP2102 driver** (Silicon Labs "CP210x USB to
   UART Bridge VCP driver"). Ram already did this on his laptop.

**Commands you will use** (run firmware commands from inside the `firmware` folder: `cd firmware`):

| Command | What it does |
|---|---|
| `pio run -e field_node_energy` | compiles that program (an "env" = one build recipe) |
| `pio run -e field_node_energy -t upload --upload-port COM6` | compiles and **flashes** (uploads) it to the board on COM6 |
| `pio device monitor --baud 115200 --port COM6 -f log2file` | shows what the board prints, and saves it to `firmware\logs\` (Ctrl+C to stop) |
| `pio device list` | lists COM ports (without telling you which board) |
| `python paper\tools\identify_ports.py` (from repo root) | resets every board and tells you which port is F, G, A, M |

**Only one program can use a COM port at a time.** Close every monitor before flashing or running a script.

Our scripts (all in `paper/tools/`, run from the repo root):
- `identify_ports.py`: which port is which board.
- `calibrate.py`: checks the INA219 against the multimeter, one load at a time.
- `run_flood_test.py`: one full attack run (baseline 60 s → defence on → 30 s → attack 120 s → recovery 60 s),
  logs every board.
- `run_e5_grid.py`: runs many of those in a row (every defence × every attack × 5 repeats).
- `paper/analysis/e5_summary.py`: turns the logs into the results table with confidence intervals.

## 8. Safety rules (read twice)

1. **Measure the adaptor before it touches any board.** It must read 4.8-5.3 V with the centre positive. 6 V or
   more: do not use it.
2. **Never two power sources on one board.** When F is powered from the adaptor through the INA219, its USB cable
   must not carry 5 V (section 9, step 1.6 explains how).
3. **Unplug power before changing any wire.** Wire with everything off, check, then power on.
4. **No 22 Ω or 10 Ω across 5 V.** Only the loads listed in step 1.5.
5. **Never use the multimeter's A/mA socket** in this project.
6. **Bare + and − must never touch.** Tape or cover the ends of stripped wires and the screw terminals when not in
   use.
7. **Touch test.** After powering a new circuit, wait 30 seconds and carefully touch the resistors and boards. Warm
   is OK. Too hot to hold, or a burning smell: unplug immediately.
8. **Disconnect the LCD, LEDs and buzzer from F** during energy runs (they draw current and spoil the numbers).

## 9. The step-by-step plan

Each step says **who/which board**, **what to do**, **what success looks like**. Do one step, check it, then the
next. Record results as you go and send logs/photos to Claude to check.

### Day 0: before touching hardware (laptop only, about 20 minutes)

**Step 0.1. Get the code and tools.** Do section 7, steps 1-4.
Success: `pio --version` prints a version number.

**Step 0.2. Find the boards.** Plug F, G, A and M into the laptop by USB. Close any open monitors. From the repo
root run `python paper\tools\identify_ports.py`.
Success: it prints a line for each board with its COM port. Write them down (for example F=COM6, G=COM9,
A=COM10, M=COM7).

**Step 0.3. Flash the right program on each board** (from `firmware`, replace COMx with that board's port):
```
pio run -e gateway -t upload --upload-port COMx           # G
pio run -e field_node_bench -t upload --upload-port COMx  # F
pio run -e attacker -t upload --upload-port COMx          # A
pio run -e monitor_ina219 -t upload --upload-port COMx    # M
```
Success: each ends with `SUCCESS`. If it says it cannot connect, hold BOOT on that board while it says
"Connecting...", then release.

**Step 0.4. Quick check that the mesh works** (all on USB, no rig). Put F and G side by side. Run
```
python paper\tools\run_flood_test.py --g COMg --f COMf --a COMa --defence gate --attack FLOOD
```
It takes about 5 minutes and you do nothing.
Success: it prints "Done. Logs:" and Claude reads the logs and confirms handshakes kept working. This checks the
boards before we build the rig.

### Day 1: build and calibrate the energy rig (about 1.5-2 hours)

**Step 1.1. Check the adaptor (multimeter, no boards involved).**
1. Turn the dial to **DC V, 20 V range**. Black probe in COM, red in VΩ.
2. Plug the adaptor into the wall. Nothing connected to its plug.
3. Put the red probe **inside** the barrel plug (the centre) and the black probe on the **outside metal sleeve**.
   (With a screw-terminal adapter fitted, measure across its + and − screws instead.)
4. Read the display.
Success: about **+4.8 to +5.3**. A minus sign means the centre is negative: stop and tell Claude. 6 V or more:
stop, do not use this adaptor.

**Step 1.2. Check the INA219 solder joints (power off).**
1. Dial to **continuity** (beep symbol). Touch the probes together: it should beep. Good.
2. On each INA219, touch one probe to a pin and the other to the pin next to it, for every neighbouring pair
   (VCC-GND, GND-SCL, SCL-SDA, SDA-Vin−, Vin−-Vin+).
Success: **no beeps** between neighbours. A beep = a solder bridge (blob of solder joining two pins): fix it before
using that board. Also look: each joint should be a shiny small cone, not a ball.

**Step 1.3. Connect the INA219 to M (power off: M unplugged).** Four jumper wires:

| INA219 pin | goes to M pin |
|---|---|
| VCC | 3V3 |
| GND | GND |
| SDA | D21 |
| SCL | D22 |

(D21 and D22 are not next to each other on the board: RX0 and TX0 sit between them. Do not use RX0/TX0.)
Then plug M into the laptop by USB and open its monitor:
`pio device monitor --baud 115200 --port COMm`
Success: you see lines starting `LOG cal n=... current_ma=...` about once per second, with current near
**-0.3 mA** (nothing is connected yet, so that is the "zero offset"). A message about "negative power" is
harmless while nothing is connected. Press Ctrl+C to close the monitor.

**Step 1.4. Measure the resistors (power off, Ω mode).** Touch the probes to the two legs of each resistor and
write the value down. Build and measure these groups (on the breadboard):
Take out 2 × 1 kΩ, 5 × 220 Ω and 5 × 270 Ω and measure each one. Every load is resistors placed **side by side
(in parallel)**: all left legs in one breadboard row, all right legs in another row, so each resistor has the full
5 V on its own.
- **L1, about 5 mA:** 1 × 1 kΩ.
- **L2, about 23 mA:** 1 × 220 Ω.
- **L3, about 70 mA:** 3 × 220 Ω side by side.
- **L4, about 117 mA:** 5 × 220 Ω side by side.
- **L5, about 213 mA:** 5 × 220 Ω and 5 × 270 Ω, all side by side.
After building each load (power off), measure across the two rows to get its total resistance.

Each resistor stays at about 0.12 W or less (half its ¼ W rating): warm at most, never hot.

**Step 1.5. Calibrate: compare the INA219 with the multimeter (one load at a time).**
Wiring for each load (adaptor **unplugged** while wiring):
```
adaptor +  ──> INA219 Vin+
INA219 Vin− ──> one end of the load
other end of the load ──> adaptor −
adaptor −  ──> M GND as well   (common ground)
```
Then:
1. Plug in the adaptor. Do the touch test (safety rule 7).
2. Multimeter on DC V: measure the voltage **across the load** (one probe each end). Write it down.
3. Close any monitor on M, then run from the repo root (put in your own numbers):
   ```
   python paper\tools\calibrate.py --port COMm --label "1 kohm" --volts 4.98 --ohms 998
   ```
   It reads M for 20 seconds and prints a row like
   `| 1 kohm | 4.980 V, 998.00 ohm, 4.99 mA | 5.02 mA | +0.60 % |`.
4. Unplug the adaptor, swap to the next load, repeat for loads L2 to L5. Also do one with **nothing** connected:
   `--label open --volts 0 --ohms 0` (that measures the zero offset).
5. Paste the rows into the table in `paper/setup.md` (the script also saves `paper/data/calibration.csv`).
Success: errors within a few percent. If an error is above about 5%, stop and send Claude the output.

**Step 1.6. Decide how F's serial log gets to the laptop without USB power.**
Problem: during energy runs F must be powered **only** through the INA219. But F's USB cable also carries 5 V
power, which would bypass the sensor. Two fixes; choose one:
- **Option 1 (simplest): a "data-only" USB cable.** Take a spare micro-USB cable, carefully open the outer cover
  in the middle, and cut and tape the **red** wire only (that is 5 V). Leave the others. Then check with the
  multimeter (continuity) that the red wire no longer connects end to end.
- **Option 2: skip F's own log during energy runs.** G already reports F's gate decisions in its log, and our
  summary script reads them from G's log. F's own serial log is then not needed: just leave out `--f` in the
  scripts. (Recommended if you are unsure about cutting cables.)

**Step 1.7. Wire F into the rig and flash it.**
1. With F on USB (normal cable), flash it: `pio run -e field_node_energy -t upload --upload-port COMf`. Then
   **unplug F's USB** (or swap to the data-only cable from 1.6).
2. Remove any LCD, LEDs or buzzer from F.
3. Wire (adaptor unplugged):
   ```
   adaptor +   ──> INA219 Vin+
   INA219 Vin− ──> F VIN
   adaptor −   ──> F GND, M GND (and INA219 GND, already on M GND)
   F D4 ──[1 kΩ resistor]──> M D4          (the "marker" wire)
   ```
   The marker wire lets F tell M "I'm starting an expensive operation now / finished now", so M can measure the
   energy of each operation separately. The 1 kΩ protects both pins.
4. Plug in the adaptor. F's red LED lights.
5. Open M's monitor: `pio device monitor --baud 115200 --port COMm -f log2file`.
Success: M prints `NRG {...}` lines every second (F's power use) and, when G does a handshake with F, rows like
`monitor,op_N,us,mJ,peak_mA`. G must be on USB and running for handshakes to happen.

### Day 2: measure (about 3-5 hours, mostly waiting)

**Step 2.1. E2: energy of each crypto operation.** Flash F with `benchmark_energy` (on USB), then put it back on
the rig (no USB 5 V). It waits 10 s idle, then runs each crypto operation 20 times, raising the marker each time.
Record M's output with `-f log2file` until it finishes. Send the log to Claude.
Gives: joules for ML-KEM keygen/encaps/decaps, ML-DSA sign/verify, AES per KB, idle power. **This is claim C1.**

**Step 2.2. Energy per real handshake, per challenge, per dropped HELLO.** Flash F back to `field_node_energy`,
rig as in 1.7, G on USB, M logging. Leave it 5 minutes. Then run a short flood (step 2.3 with `--reps 1`) so M
sees challenges and drops too. Claude computes the challenge cost from this and replaces the 0.0005 J
placeholder in the gate settings, then you reflash F.

**Step 2.3. E5: the attack grid.** Everything on the laptop except F (on the rig). First a dry run to see the
plan and how long it takes:
```
python paper\tools\run_e5_grid.py --g COMg --f COMf --a COMa --m COMm --reps 1 --dry-run
```
Then the real thing, first with 1 repeat (smoke test, about 1 hour), then 5 repeats (about 5 hours; you can leave
it running and come back):
```
python paper\tools\run_e5_grid.py --g COMg --f COMf --a COMa --m COMm --reps 5
```
(If F has no data cable on the rig, leave out `--f COMf`. G's log still carries F's counters, and the summary
script reads them from there.)
Extra grids, same command with:
- rate sweep: `--defences none gate --attacks FLOOD --rates 5 20 50`
- echo attacker: `--defences cookie gate --attacks INSIDER --echo --tag echo`
- gate v1 comparison: reflash F with `field_node_bench_gatev1`, then `--defences gate --tag v1`
Success: logs appear in `paper\data\E_phase6\runs\`, and `python paper\analysis\e5_summary.py` prints a table.
**This is claims C2 and C3.**

**Step 2.4. Record each run** in `paper/runlog.csv` (date, boards, distance, defence, attack, notes). A bad run
gets `excluded=y` and a reason; never delete it.

### Day 3: analysis and writing (mostly Claude, the team reviews)

- Claude turns the logs into tables and figures with scripts in `paper/analysis/` (anyone can rerun them).
- Retrain EnergyGate on the recorded traces instead of simulated ones, and report the honest held-out results.
- Write the paper sections: method, threat model, results, limitations.

### Decisions the team must make (Claude will not guess these)

1. **Battery or not?** With a small LiPo battery (300-500 mAh) we can measure real time-to-dead (experiment E4).
   Without one, we report joules and label battery life as SIMULATED. Buying one also needs a charger module;
   ask Claude for the exact part before buying.
2. **F's log during energy runs:** option 1 or 2 in step 1.6.
3. **The teammate branch `v4-esp-now-and-handshake`** (HMAC-PSK version) is not merged and conflicts with ours.
   Keep it separate or drop it?
4. **Who has the boards?** They were with Ram. Whoever does the hardware needs all four boards, both INA219s,
   the adaptor, the multimeter, resistors, breadboard and jumper wires.

## 10. When something goes wrong

| What you see | Likely cause | Fix |
|---|---|---|
| Board not in `pio device list` | charge-only cable, or no driver | try another cable; install CP210x driver |
| "Access denied" / "could not open port" | a monitor or script is already using that port | close all monitors (Ctrl+C), retry |
| Flash stuck at "Connecting..." | board not in download mode | hold BOOT, press EN, release BOOT, retry |
| M prints no `LOG cal` lines | INA219 wiring | check VCC→3V3, GND→GND, SDA→D21, SCL→D22, unplug and replug M |
| "negative power ... swapped?" on M | nothing connected (harmless) or Vin+ and Vin− swapped | if a load is connected, swap Vin+ and Vin− |
| "Bus already started in Master Mode" | harmless | ignore |
| Handshakes time out often | boards too far apart (weak signal) | put F and G right next to each other |
| Reading jumps or is far off | missing common ground | connect adaptor − to M GND |
| `git pull` refuses (files would be overwritten) | local log copies | move the local folder aside, then pull |

## 11. Glossary

- **Env (PlatformIO)**: one build recipe; decides which program and options go on a board.
- **Flash / upload**: copy a compiled program onto the board.
- **Firmware**: the program running on the board.
- **Serial monitor**: the text the board prints over USB.
- **MAC address**: a board's fixed radio ID.
- **HELLO / RESPONSE / CONFIRM**: the three handshake messages.
- **Fragment**: one radio packet carrying part of a big message.
- **Spend / Challenge / Drop**: EnergyGate's three decisions.
- **Joule budget**: the field node's energy allowance that limits worst-case drain.
- **INA219**: the current/voltage sensor. **Shunt**: its tiny measuring resistor.
- **Marker (GPIO4)**: the wire F uses to tell M when an operation starts and stops.
- **Calibration**: checking the sensor against the multimeter so readers trust our numbers.
- **Held-out / group split**: testing a model on data it never saw, recorded separately; the honest way to report.
- **SIMULATED**: produced by our own generator or placeholder, not measured. Must be labelled in the paper.
- **CI (95% confidence interval)**: the range the true value probably lies in; needs repeated runs.
