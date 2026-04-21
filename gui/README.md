# LIN Bus Analyzer — Windows GUI Application

## Requirements
- Python 3.8+
- Windows 10/11

## Installation

```bash
cd gui
pip install -r requirements.txt
```

## Launch

```bash
python app.py
```

## Features

### Sniffer Dashboard
- **Full Header Scan**: Iterates all 64 LIN IDs (0x00–0x3F)
- **Progress Bar**: Real-time scan progress with responsive ID counter
- **Results Table**: Displays ID, Protected ID (PID), DLC, and raw hex data
- **Checksum Toggle**: Switch between Enhanced (LIN 2.x) and Classic (LIN 1.x)
- **Bus Wake**: Send a dominant wake-up pulse to initialise slave nodes
- **CSV Export**: Save scan results for external analysis

### Fuzzer Dashboard
- **Auto-Skip**: Excludes known Status IDs from fuzz targets
- **Hit Detection**: Before/after comparison highlights state changes
- **Event Log**: Timestamped scrolling log of all fuzz activity
- **3-Stage Strategy**: Single-byte sweep → two-byte sweep → common patterns

### Manual Trigger & Decode
- **Trigger Buttons**: One-click resend of any discovered fuzz payload
- **Notes Fields**: Inline text entry for documenting physical seat responses
- **Custom Frame Sender**: Build and send arbitrary LIN frames
- **Function Map**: Aggregated command-to-function mapping with CSV/JSON export

## Architecture

```
app.py              ← Main window, menu, notebook, queue polling
├── serial_manager.py ← Background thread serial I/O
├── sniffer_tab.py    ← Sniffer Dashboard UI
├── fuzzer_tab.py     ← Fuzzer Dashboard UI
├── manual_tab.py     ← Manual Trigger & Decode UI
├── styles.py         ← Theme, fonts, colour constants
└── requirements.txt  ← Dependencies
```

## Theming
Uses [ttkbootstrap](https://ttkbootstrap.readthedocs.io/) with the **cyborg**
dark theme. All hex data is rendered in Consolas monospace; UI elements use
Segoe UI. Responsive IDs are highlighted in green, fuzz hits in orange.
