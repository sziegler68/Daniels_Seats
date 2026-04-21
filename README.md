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

## Hardware Requirements

| Component | Detail |
|-----------|--------|
| MCU | Arduino Nano Every (ATmega4809) |
| Transceiver | GODIYMODULES TJA1021 (Master Mode) |
| Serial1 | TX1=Pin 1, RX1=Pin 0 → TJA1021 TXD/RXD |
| NSLP Pin | D2 → TJA1021 NSLP (or tied to 5V) |
| LIN Bus | 19,200 baud, single-wire, 12V supply |
| USB | 115,200 baud (PC communication) |

## Quick Start

### 1. Flash the Firmware
1. Open `firmware/lin_sniffer_fuzzer/lin_sniffer_fuzzer.ino` in the Arduino IDE
2. Select **Board: Arduino Nano Every**
3. Select the correct COM port
4. Upload

### 2. Launch the GUI
```bash
cd gui
pip install -r requirements.txt
python app.py
```

### 3. Workflow
1. **Connect** — Select the Arduino's COM port and click Connect
2. **Sniff** — Run a full header scan to discover responsive Status IDs
3. **Fuzz** — Automatically cycle through unused IDs with payload injection
4. **Trigger** — Resend discovered commands and document physical responses
5. **Export** — Save the function map as CSV or JSON

## Serial Protocol

See `firmware/README.md` for the complete PC ↔ Arduino command reference.
