# LIN Bus Analyzer — Lexus IS350 Seat ECU Reverse Engineering Toolchain

A two-component toolchain for sniffing, fuzzing, and decoding the LIN-Bus
commands of a 2015 Lexus IS350 climate-controlled seat ECU for retrofit
into an analog vehicle (Toyota 4Runner).

## System Architecture

```
┌──────────────┐    USB 115200    ┌───────────────────┐   LIN 19200   ┌──────────┐
│   Windows    │◄────────────────►│  Arduino Nano     │◄─────────────►│  Lexus   │
│   GUI App    │   Serial ASCII   │  Every + TJA1021  │  Single-wire  │  Seat    │
│  (Python)    │                  │  (LIN Master)     │  12V bus      │  ECU     │
└──────────────┘                  └───────────────────┘               └──────────┘
```

## Components

### Arduino Firmware (`firmware/`)
- **LIN Bus Library** — Break generation, parity, Enhanced/Classic checksums
- **Sniffer Module** — Scans all 64 IDs, detects responsive slaves and DLCs
- **Fuzzer Module** — Injects payloads into unused IDs, monitors for state changes

### Windows GUI (`gui/`)
- **Sniffer Dashboard** — Progress bar, responsive ID table, CSV export
- **Fuzzer Dashboard** — Hit detection table, before/after comparison, event log
- **Manual Trigger** — One-click resend, notes fields, function map export (CSV/JSON)

## Hardware Requirements & Wiring

### 1. Arduino Nano Every
- **Microcontroller**: ATmega4809
- **USB**: 115,200 baud (PC communication)

### 2. LIN Transceiver (TJA1021 - GODIYMODULES Master Mode)
- **TX / RX**: Serial1 (TX1 = Pin 1, RX1 = Pin 0)
- **NSLP (Sleep/Wake)**: Pin **D2** (or tie to 5V)
- **LIN Bus**: Single-wire, 19,200 baud
- **Power**: 12V from bench supply / seat circuit

### 3. Current Sensor (INA260 Breakout)
- **Purpose**: Detects physical seat activations (Silent Hits) & provides 12A safety cutoff.
- **I2C Interface**: SDA = **A4**, SCL = **A5**
- **Hardware Alert**: Pin **D3** (Active-LOW, triggers on > 12A)
- **Power Rating**: 15A max continuous
- **Wiring**: Place `VIN+` / `VIN-` **in series** with the seat module's 12V power supply lead.

## Quick Start & Workflow

### 1. Flash the Firmware
1. Open `firmware/lin_sniffer_fuzzer/lin_sniffer_fuzzer.ino` in the Arduino IDE.
2. Install the `Adafruit_INA260` library via Library Manager.
3. Select **Board: Arduino Nano Every** and upload.

### 2. Launch the GUI
```bash
cd gui
pip install -r requirements.txt
python app.py
```

### 3. Step-by-Step Usage

1. **Connect**
   - Select the Arduino's COM port in the upper left and click Connect.
   - The Arduino will automatically wake the LIN bus and capture idle baselines.

2. **Phase 1: Sniffing (Discover Status IDs)**
   - Go to the **Sniffer** tab.
   - Click **Run Full Scan**. The Arduino will probe IDs `0x00` through `0x3B`.
   - Responsive slave IDs will populate in the table. These are the IDs the seat uses to report its status.

3. **Phase 2: Fuzzing (Discover Action IDs)**
   - Go to the **Fuzzer** tab.
   - Click **Start Fuzz**. The Arduino will inject payloads into all unused IDs and monitor for responses.
   - **Orange Hits (LIN Status):** A payload caused a change in the data of a known Status ID.
   - **Purple Hits (Current Spike):** A payload caused a physical component to activate detected by the INA260.
   - *Hardware Auto-Pause:* The Arduino will immediately halt its sweep upon detecting a current spike to guarantee the exact triggering payload is captured.
   - *Automated Verification Loop:* The GUI will automatically loop the suspect frame for 60 seconds. If the current remains elevated >0.1A above baseline, it logs a **True Hit**. If the current drops back to baseline, it logs a **False Positive** (strikethrough) and automatically resumes the fuzzing sweep.
   - *Baseline Recalibration:* The firmware automatically recaptures the idle current baseline before starting every new Action ID to prevent false hits caused by ECU warm-up drift.
   - *Speed Optimization:* Polling Status IDs slows the fuzzer down from 16ms/frame to ~1s/frame. If you only care about Current Spikes, clear your imported Status CSVs to scan an entire Action ID in 45 seconds instead of 25 minutes.

4. **Phase 3: Trigger & Map**
   - Go to the **ID Mapper** / Manual tab.
   - Review the discovered hits. Use the manual controls to re-send payloads and physically observe what they do.
   - Classify each command (e.g., "Heater High", "Fan Low").

5. **Phase 4: Export**
   - Export your classified mappings to JSON/CSV for use in your final retrofit microcontroller.

## Serial Protocol

See `firmware/README.md` for the complete PC ↔ Arduino command reference.
