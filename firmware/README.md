# Arduino Firmware — LIN Bus Sniffer & Fuzzer

## Build Requirements
- **Arduino IDE** 2.x or **arduino-cli**
- **Board Package**: Arduino megaAVR Boards (for Nano Every / ATmega4809)
- No external libraries required — the LIN protocol is implemented from scratch

## Pin Wiring

| Arduino Pin | Connection | Notes |
|-------------|-----------|-------|
| Pin 0 (RX1) | TJA1021 TXD (to Arduino) | Serial1 RX |
| Pin 1 (TX1) | TJA1021 RXD (from Arduino) | Serial1 TX |
| Pin D2 | TJA1021 NSLP | Sleep control (or tie to 5V) |
| USB | PC | 115200 baud command channel |

**If NSLP is tied to 5V:** Change `#define SLP_PIN 2` to `#define SLP_PIN LIN_SLP_PIN_DISABLED` in `lin_sniffer_fuzzer.ino`.

## Upload

```bash
# Arduino IDE: select Board → Arduino Nano Every, then Upload

# Or with arduino-cli:
arduino-cli compile --fqbn arduino:megaavr:nona4809 firmware/lin_sniffer_fuzzer
arduino-cli upload  --fqbn arduino:megaavr:nona4809 -p COM3 firmware/lin_sniffer_fuzzer
```

## Serial Command Protocol (115200 baud, ASCII, newline-terminated)

### PC → Arduino

| Command | Format | Description |
|---------|--------|-------------|
| PING | `PING` | Health check |
| Start Sniff | `START_SNIFF` | Scan all 64 IDs |
| Stop Sniff | `STOP_SNIFF` | Abort scan |
| Start Fuzz | `START_FUZZ:SKIP=15,2A` | Fuzz unused IDs (skip = status IDs) |
| Stop Fuzz | `STOP_FUZZ` | Abort fuzz |
| Send Frame | `SEND_FRAME:ID=0A,DLC=2,DATA=00_42` | Manual injection |
| Set Checksum | `SET_CKSUM:ENHANCED` or `SET_CKSUM:CLASSIC` | Toggle mode |
| Wake Bus | `WAKE_BUS` | Send dominant wake-up pulse |
| Monitor | `MONITOR:IDS=15,2A,30` | Continuous polling |
| Stop Monitor | `STOP_MONITOR` | Stop polling |

### Arduino → PC

| Response | Format | Description |
|----------|--------|-------------|
| PONG | `PONG` | Health check reply |
| SNIFF_PROGRESS | `SNIFF_PROGRESS:ID=0A,TOTAL=64` | Scan position |
| STATUS_FOUND | `STATUS_FOUND:ID=15,DLC=4,DATA=00_FF_00_12` | Responsive ID |
| SNIFF_DONE | `SNIFF_DONE:COUNT=7` | Scan complete |
| FUZZ_SENDING | `FUZZ_SENDING:ID=0A,DLC=2,DATA=00_42` | Current payload |
| FUZZ_HIT | `FUZZ_HIT:ACTION_ID=0A,...,STATUS_ID=15,BEFORE=...,AFTER=...` | State change |
| FUZZ_DONE | `FUZZ_DONE` | Fuzz complete |
| MONITOR_DATA | `MONITOR_DATA:ID=15,DLC=4,DATA=00_FF_00_12` | Poll result |
| FRAME_SENT | `FRAME_SENT:ID=0A` | Manual frame confirmation |
| ERROR | `ERROR:MSG=<description>` | Error |
| INFO | `INFO:MSG=<description>` | Informational |

### Data Format Convention
- IDs: 2-digit uppercase hex (e.g. `0A`, `3F`)
- Data bytes: underscore-separated uppercase hex (e.g. `FF_00_A3_12`)
- IDs are raw 6-bit values (0x00–0x3F), not Protected IDs

## Module Architecture

```
lin_sniffer_fuzzer.ino     ← Main sketch (command parser, state management)
├── lin_bus.h / .cpp       ← LIN protocol engine (break, parity, checksum, I/O)
├── sniffer.h / .cpp       ← Header scan module (iterates all 64 IDs)
└── fuzzer.h / .cpp        ← Payload injection module (3-stage strategy)
```

## Technical Notes

### Break Field Generation
The ATmega4809 USART does not expose a hardware LIN break mode through the
Arduino core. The firmware uses a manual TX-pin-drive method:
1. Flush pending TX and disable the USART transmitter
2. Drive the TX pin LOW for 14 bit-times (~730 µs at 19200 baud)
3. Drive HIGH for 1 bit-time (~52 µs) as the break delimiter
4. Re-enable the USART transmitter

### DLC Detection
LIN headers don't contain a DLC field. The sniffer reads all response bytes
until an inter-byte timeout, then validates the checksum for DLC = N-1 down
to 1. The first matching DLC is reported.

### Diagnostic Frame Exception
IDs 60 (0x3C) and 61 (0x3D) always use the Classic checksum regardless of
the selected mode, per the LIN specification.
