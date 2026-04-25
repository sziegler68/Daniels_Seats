/**
 * ═══════════════════════════════════════════════════════════════════
 *  LIN Bus Sniffer & Fuzzer — Main Sketch
 *  Lexus IS350 Seat ECU Reverse Engineering Toolchain
 * ═══════════════════════════════════════════════════════════════════
 * 
 * Hardware:
 *   MCU:         Arduino Nano Every (ATmega4809)
 *   Transceiver: GODIYMODULES TJA1021 (Master Mode)
 *   LIN Bus:     19,200 baud on Serial1 (TX1=Pin1, RX1=Pin0)
 *   USB:         115,200 baud on Serial  (PC communication)
 *   NSLP Pin:    D2 → TJA1021 NSLP  (or set to LIN_SLP_PIN_DISABLED)
 * 
 * Serial Protocol:
 *   PC → Arduino commands are line-terminated ASCII strings.
 *   Arduino → PC responses use the format: TYPE:KEY=VAL,KEY=VAL,...
 *   See the implementation plan or README for the full protocol spec.
 * 
 * ═══════════════════════════════════════════════════════════════════
 */

#include "lin_bus.h"
#include "sniffer.h"
#include "fuzzer.h"
#include "current_sensor.h"


// ─────────────────────────────────────────────────────────────────
//  Pin & Baud Configuration
// ─────────────────────────────────────────────────────────────────

// TJA1021 NSLP pin.  Set to LIN_SLP_PIN_DISABLED (255) if the
// GODIYMODULES board ties NSLP directly to the 5V rail.
#define SLP_PIN     2

// INA260 ALERT pin (hardware interrupt for overcurrent safety).
// D3 chosen because D2 is taken by TJA1021 SLP_PIN.
#define INA260_ALERT_PIN  3

// Serial1 TX pin — needed for manual break field generation.
#define TX1_PIN     PIN_SERIAL1_TX

// Baud rates
#define LIN_BAUD    19200      // LIN bus speed
#define USB_BAUD    115200     // PC ↔ Arduino speed


// ─────────────────────────────────────────────────────────────────
//  Global Objects
// ─────────────────────────────────────────────────────────────────

LinBus         lin(Serial1, TX1_PIN, SLP_PIN, LIN_BAUD);
Sniffer        sniffer;
Fuzzer         fuzzer;
CurrentSensor  currentSensor;

// Overcurrent ISR flag — set by hardware interrupt, checked in loop()
volatile bool overcurrentTriggered = false;


// ─────────────────────────────────────────────────────────────────
//  Monitoring State
// ─────────────────────────────────────────────────────────────────

bool     monitoringActive = false;
uint8_t  monitorIds[LIN_NUM_IDS];
uint8_t  monitorIdCount   = 0;
unsigned long lastMonitorPoll = 0;

#define MONITOR_INTERVAL_MS  100


// ─────────────────────────────────────────────────────────────────
//  Serial Input Buffer
// ─────────────────────────────────────────────────────────────────

String inputBuffer = "";


// ─────────────────────────────────────────────────────────────────
//  Forward Declarations
// ─────────────────────────────────────────────────────────────────

void handleCommand(const String& cmd);
void parseSendFrame(const String& cmd);
void parseMonitorCommand(const String& cmd);
void pollMonitoredIds();
void onOvercurrent();


// ═════════════════════════════════════════════════════════════════
//  setup()
// ═════════════════════════════════════════════════════════════════

void setup() {
    Serial.begin(USB_BAUD);
    while (!Serial) { ; }   // Wait for USB CDC to enumerate

    lin.begin();
    sniffer.begin(&lin);
    fuzzer.begin(&lin, &sniffer, &currentSensor);

    // ── INA260 Current Sensor ────────────────────────────────────
    if (currentSensor.begin(INA260_ALERT_PIN)) {
        currentSensor.captureBaseline();
        Serial.print("INFO:MSG=INA260 ready. Idle baseline: ");
        Serial.print(currentSensor.getBaselineMA(), 1);
        Serial.println(" mA");

        // Attach hardware interrupt for overcurrent safety (12 A)
        attachInterrupt(
            digitalPinToInterrupt(INA260_ALERT_PIN),
            onOvercurrent, FALLING
        );
    } else {
        Serial.println("INFO:MSG=INA260 not detected — current sensing disabled");
    }

    Serial.println("INFO:MSG=LIN Sniffer/Fuzzer Ready (Nano Every + TJA1021)");
    Serial.println("INFO:MSG=Send PING to verify connection");
}


// ═════════════════════════════════════════════════════════════════
//  loop()
// ═════════════════════════════════════════════════════════════════

void loop() {
    // ── Read and buffer serial commands ──────────────────────────
    while (Serial.available()) {
        char c = Serial.read();
        if (c == '\n' || c == '\r') {
            if (inputBuffer.length() > 0) {
                inputBuffer.trim();
                handleCommand(inputBuffer);
                inputBuffer = "";
            }
        } else {
            inputBuffer += c;
        }
    }

    // ── Overcurrent safety check ──────────────────────────────
    if (overcurrentTriggered) {
        overcurrentTriggered = false;

        // Immediately halt all operations
        sniffer.requestStop();
        fuzzer.requestStop();
        monitoringActive = false;

        // Report to GUI
        float currentMA = currentSensor.readCurrentMA();
        Serial.print("EMERGENCY_STOP:OVERCURRENT,AMP=");
        Serial.println(currentMA / 1000.0f, 2);

        // Clear the INA260 latched alert so it can re-trigger
        currentSensor.clearAlert();
    }

    // ── Continuous monitoring (when active and no scan/fuzz running)
    if (monitoringActive && !sniffer.isRunning() && !fuzzer.isRunning()) {
        if (millis() - lastMonitorPoll >= MONITOR_INTERVAL_MS) {
            pollMonitoredIds();
            lastMonitorPoll = millis();
        }
    }
}


// ═════════════════════════════════════════════════════════════════
//  Command Dispatcher
// ═════════════════════════════════════════════════════════════════

void handleCommand(const String& cmd) {

    // ── Health check ─────────────────────────────────────────────
    if (cmd == "PING") {
        Serial.println("PONG");
    }

    // ── Sniffer controls ─────────────────────────────────────────
    else if (cmd == "START_SNIFF") {
        if (sniffer.isRunning() || fuzzer.isRunning()) {
            Serial.println("ERROR:MSG=Another operation is already running");
            return;
        }
        sniffer.scanAll();
    }
    else if (cmd == "STOP_SNIFF") {
        sniffer.requestStop();
    }

    // ── Fuzzer controls ──────────────────────────────────────────
    else if (cmd.startsWith("START_FUZZ")) {
        if (sniffer.isRunning() || fuzzer.isRunning()) {
            Serial.println("ERROR:MSG=Another operation is already running");
            return;
        }

        // Parse skip IDs from: START_FUZZ:SKIP=15,2A,30
        uint8_t skipIds[LIN_NUM_IDS];
        uint8_t skipCount = 0;

        int skipIdx = cmd.indexOf("SKIP=");
        if (skipIdx >= 0) {
            String skipStr = cmd.substring(skipIdx + 5);
            while (skipStr.length() > 0 && skipCount < LIN_NUM_IDS) {
                int commaIdx = skipStr.indexOf(',');
                String idStr;
                if (commaIdx >= 0) {
                    idStr   = skipStr.substring(0, commaIdx);
                    skipStr = skipStr.substring(commaIdx + 1);
                } else {
                    idStr   = skipStr;
                    skipStr = "";
                }
                idStr.trim();
                if (idStr.length() > 0) {
                    skipIds[skipCount++] =
                        (uint8_t)strtol(idStr.c_str(), NULL, 16);
                }
            }
        }

        fuzzer.startFuzz(skipIds, skipCount);
    }
    else if (cmd == "STOP_FUZZ") {
        fuzzer.requestStop();
    }
    else if (cmd == "RECAPTURE_BASELINE") {
        // If the fuzzer is running, it will pick this up via checkForStop().
        // If idle, just acknowledge — baseline is auto-captured on next fuzz start.
        if (fuzzer.isRunning()) {
            // The fuzzer's checkForStop() handles this inline
        }
        // Also re-baseline the current sensor
        if (currentSensor.isAvailable()) {
            currentSensor.captureBaseline();
            Serial.print("INFO:MSG=INA260 baseline recaptured: ");
            Serial.print(currentSensor.getBaselineMA(), 1);
            Serial.println(" mA");
        }
        Serial.println("INFO:MSG=Baseline recapture requested");
    }

    // ── Manual frame injection ───────────────────────────────────
    else if (cmd.startsWith("SEND_FRAME")) {
        parseSendFrame(cmd);
    }

    // ── Checksum mode ────────────────────────────────────────────
    else if (cmd.startsWith("SET_CKSUM")) {
        if (cmd.indexOf("ENHANCED") >= 0) {
            lin.setChecksumMode(true);
            Serial.println("INFO:MSG=Checksum set to Enhanced (LIN 2.x)");
        } else if (cmd.indexOf("CLASSIC") >= 0) {
            lin.setChecksumMode(false);
            Serial.println("INFO:MSG=Checksum set to Classic (LIN 1.x)");
        }
    }

    // ── Bus wake-up ──────────────────────────────────────────────
    else if (cmd == "WAKE_BUS") {
        lin.wakeBusDominant();
        Serial.println("INFO:MSG=Bus wake-up pulse sent");
    }

    // ── Continuous monitoring ────────────────────────────────────
    else if (cmd.startsWith("MONITOR")) {
        parseMonitorCommand(cmd);
    }
    else if (cmd == "STOP_MONITOR") {
        monitoringActive = false;
        monitorIdCount   = 0;
        Serial.println("INFO:MSG=Monitoring stopped");
    }

    // ── Baud rate change ─────────────────────────────────────────
    else if (cmd.startsWith("SET_BAUD")) {
        // Expected format: SET_BAUD:RATE=19200
        int rateIdx = cmd.indexOf("RATE=");
        if (rateIdx >= 0) {
            String rateStr = cmd.substring(rateIdx + 5);
            rateStr.trim();
            uint32_t newBaud = (uint32_t)rateStr.toInt();

            if (newBaud >= 1200 && newBaud <= 20000) {
                lin.setBaudRate(newBaud);
                Serial.print("INFO:MSG=LIN baud rate set to ");
                Serial.println(newBaud);
            } else {
                Serial.println("ERROR:MSG=Invalid baud rate (must be 1200-20000)");
            }
        } else {
            Serial.println("ERROR:MSG=Invalid SET_BAUD format. "
                            "Expected: SET_BAUD:RATE=19200");
        }
    }

    // ── Unknown command ──────────────────────────────────────────
    else {
        Serial.print("ERROR:MSG=Unknown command: ");
        Serial.println(cmd);
    }
}


// ═════════════════════════════════════════════════════════════════
//  SEND_FRAME Parser
// ═════════════════════════════════════════════════════════════════

void parseSendFrame(const String& cmd) {
    // Expected format: SEND_FRAME:ID=0A,DLC=2,DATA=00_42
    int idIdx   = cmd.indexOf("ID=");
    int dlcIdx  = cmd.indexOf("DLC=");
    int dataIdx = cmd.indexOf("DATA=");

    if (idIdx < 0 || dlcIdx < 0 || dataIdx < 0) {
        Serial.println("ERROR:MSG=Invalid SEND_FRAME format. "
                        "Expected: SEND_FRAME:ID=XX,DLC=N,DATA=XX_XX...");
        return;
    }

    // Parse ID
    String idStr = cmd.substring(idIdx + 3, cmd.indexOf(',', idIdx));
    uint8_t id   = (uint8_t)strtol(idStr.c_str(), NULL, 16);

    // Parse DLC
    String dlcStr = cmd.substring(dlcIdx + 4, cmd.indexOf(',', dlcIdx));
    uint8_t dlc   = (uint8_t)dlcStr.toInt();

    if (dlc == 0 || dlc > LIN_MAX_DATA_LEN) {
        Serial.println("ERROR:MSG=Invalid DLC (must be 1-8)");
        return;
    }

    // Parse DATA bytes (underscore-separated hex)
    String dataStr = cmd.substring(dataIdx + 5);
    uint8_t data[LIN_MAX_DATA_LEN];
    uint8_t dataCount = 0;

    while (dataStr.length() > 0 && dataCount < dlc) {
        int sepIdx = dataStr.indexOf('_');
        String byteStr;
        if (sepIdx >= 0) {
            byteStr = dataStr.substring(0, sepIdx);
            dataStr = dataStr.substring(sepIdx + 1);
        } else {
            byteStr = dataStr;
            dataStr = "";
        }
        byteStr.trim();
        if (byteStr.length() > 0) {
            data[dataCount++] = (uint8_t)strtol(byteStr.c_str(), NULL, 16);
        }
    }

    if (dataCount != dlc) {
        Serial.println("ERROR:MSG=Data byte count does not match DLC");
        return;
    }

    // Transmit the frame
    lin.sendHeader(id);
    lin.sendResponse(id, data, dlc);

    Serial.print("FRAME_SENT:ID=");
    if (id < 0x10) Serial.print("0");
    Serial.println(id, HEX);
}


// ═════════════════════════════════════════════════════════════════
//  MONITOR Parser
// ═════════════════════════════════════════════════════════════════

void parseMonitorCommand(const String& cmd) {
    // Expected format: MONITOR:IDS=15,2A,30
    int idsIdx = cmd.indexOf("IDS=");
    if (idsIdx < 0) {
        Serial.println("ERROR:MSG=Invalid MONITOR format. "
                        "Expected: MONITOR:IDS=XX,XX,...");
        return;
    }

    monitorIdCount = 0;
    String idsStr  = cmd.substring(idsIdx + 4);

    while (idsStr.length() > 0 && monitorIdCount < LIN_NUM_IDS) {
        int commaIdx = idsStr.indexOf(',');
        String idStr;
        if (commaIdx >= 0) {
            idStr  = idsStr.substring(0, commaIdx);
            idsStr = idsStr.substring(commaIdx + 1);
        } else {
            idStr  = idsStr;
            idsStr = "";
        }
        idStr.trim();
        if (idStr.length() > 0) {
            monitorIds[monitorIdCount++] =
                (uint8_t)strtol(idStr.c_str(), NULL, 16);
        }
    }

    monitoringActive = true;
    lastMonitorPoll  = millis();

    Serial.print("INFO:MSG=Monitoring ");
    Serial.print(monitorIdCount);
    Serial.println(" IDs");
}


// ═════════════════════════════════════════════════════════════════
//  Continuous ID Polling
// ═════════════════════════════════════════════════════════════════

void pollMonitoredIds() {
    for (uint8_t i = 0; i < monitorIdCount; i++) {
        uint8_t id = monitorIds[i];
        uint8_t dataBuf[LIN_MAX_DATA_LEN];
        uint8_t dlc = 0;

        lin.sendHeader(id);
        bool valid = lin.readResponse(id, dataBuf, dlc);

        if (valid && dlc > 0) {
            // Format: MONITOR_DATA:ID=15,DLC=4,DATA=00_FF_00_12
            Serial.print("MONITOR_DATA:ID=");
            if (id < 0x10) Serial.print("0");
            Serial.print(id, HEX);
            Serial.print(",DLC=");
            Serial.print(dlc);
            Serial.print(",DATA=");

            for (uint8_t j = 0; j < dlc; j++) {
                if (j > 0) Serial.print("_");
                if (dataBuf[j] < 0x10) Serial.print("0");
                Serial.print(dataBuf[j], HEX);
            }
            Serial.println();
        }

        delay(LIN_INTERFRAME_DELAY_MS);
    }
}


// ═════════════════════════════════════════════════════════════════
//  INA260 Overcurrent ISR
// ═════════════════════════════════════════════════════════════════

void onOvercurrent() {
    // Minimal ISR: just set the flag.  All heavy work (serial print,
    // alert clearing, fuzzer stop) happens in loop() context.
    overcurrentTriggered = true;
}
