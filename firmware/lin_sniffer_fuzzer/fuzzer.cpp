/**
 * LIN Bus Fuzzer Module — Implementation
 * 
 * Workflow per Action ID:
 *   1. Take baseline snapshot of all known Status IDs
 *   2. For each candidate DLC (2, 4, 8), run a Full Byte Sweep:
 *      a. For each byte position (0 to DLC-1):
 *         i.   Set all payload bytes to 0x00
 *         ii.  Sweep the target byte from 0x00 to 0xFF
 *         iii. For each value:
 *              - Read INA260 baseline current (~1ms)
 *              - Send header + response (~10ms)
 *              - Poll all Status IDs (~50-60ms natural delay)
 *              - Read INA260 active current (~1ms)
 *              - Compare for LIN hits and amp hits
 *         iv.  If amp hit: inject all-zeros cooldown, poll for decay
 *   3. Move to next Action ID
 * 
 * Only scans IDs 0–59 (0x00–0x3B).  IDs 60–63 are reserved per
 * LIN 2.x spec and excluded from automated fuzzing.
 * 
 * The fuzzer checks for STOP_FUZZ commands between every attempt
 * to remain responsive to user abort requests.
 */

#include "fuzzer.h"
#include "current_sensor.h"


Fuzzer::Fuzzer()
    : _lin(nullptr)
    , _sniffer(nullptr)
    , _currentSensor(nullptr)
    , _running(false)
    , _stopRequested(false)
    , _recaptureRequested(false)
    , _blacklistCount(0)
{
}


void Fuzzer::begin(LinBus* lin, Sniffer* sniffer, CurrentSensor* cs) {
    _lin           = lin;
    _sniffer       = sniffer;
    _currentSensor = cs;
}


// ─────────────────────────────────────────────────────────────────
//  Main Fuzz Entry Point
// ─────────────────────────────────────────────────────────────────

void Fuzzer::startFuzz(const uint8_t* skipIds, uint8_t skipCount) {
    if (!_lin || !_sniffer || _running) return;

    _running              = true;
    _stopRequested        = false;
    _recaptureRequested   = false;

    // ── Build the Status ID list (IDs we monitor for changes) ──
    // Only consider IDs within the safe scan range (0–0x3B)
    uint8_t statusIds[LIN_NUM_IDS];
    uint8_t statusCount = 0;

    for (uint8_t i = 0; i <= LIN_MAX_SCAN_ID; i++) {
        if (_sniffer->isActive(i)) {
            statusIds[statusCount++] = i;
        }
    }

    // ── Build the Action ID list (IDs we will fuzz) ────────────
    // Only consider IDs within the safe scan range (0–0x3B)
    uint8_t actionIds[LIN_NUM_IDS];
    uint8_t actionCount = 0;

    for (uint8_t id = 0; id <= LIN_MAX_SCAN_ID; id++) {
        bool skip = false;

        // Skip known responsive Status IDs
        for (uint8_t s = 0; s < statusCount; s++) {
            if (id == statusIds[s]) { skip = true; break; }
        }
        // Skip any IDs explicitly excluded by the GUI
        for (uint8_t s = 0; s < skipCount; s++) {
            if (id == skipIds[s]) { skip = true; break; }
        }

        if (!skip) {
            actionIds[actionCount++] = id;
        }
    }

    Serial.print("INFO:MSG=Fuzzing ");
    Serial.print(actionCount);
    Serial.print(" action IDs, monitoring ");
    Serial.print(statusCount);
    Serial.println(" status IDs (Full Byte Sweep, DLC={2,4,8})");

    // Wake the bus in case the slave entered sleep after inactivity
    _lin->wakeBusDominant();
    Serial.println("INFO:MSG=Bus wake-up pulse sent");

    // ── Iterate through each Action ID ─────────────────────────
    for (uint8_t a = 0; a < actionCount; a++) {
        if (checkForStop()) {
            Serial.println("INFO:MSG=Fuzz aborted by user");
            break;
        }

        uint8_t actionId = actionIds[a];

        // Progress info
        Serial.print("INFO:MSG=Fuzzing ID 0x");
        if (actionId < 0x10) Serial.print("0");
        Serial.print(actionId, HEX);
        Serial.print(" (");
        Serial.print(a + 1);
        Serial.print("/");
        Serial.print(actionCount);
        Serial.println(")");

        // Fresh baseline before each new Action ID
        captureBaseline(statusIds, statusCount);

        // Standard LIN DLC lengths: 2, 4, 8 bytes
        // (DLC 1,3,5,6,7 are non-standard and will be checksum-rejected)
        static const uint8_t DLC_CANDIDATES[] = {2, 4, 8};
        static const uint8_t DLC_CANDIDATE_COUNT = 3;

        for (uint8_t d = 0; d < DLC_CANDIDATE_COUNT; d++) {
            uint8_t dlc = DLC_CANDIDATES[d];

            // Check if the GUI requested a baseline recapture mid-run
            if (_recaptureRequested) {
                _recaptureRequested = false;
                captureBaseline(statusIds, statusCount);
                if (_currentSensor && _currentSensor->isAvailable()) {
                    _currentSensor->captureBaseline();
                }
                Serial.println("INFO:MSG=Baseline recaptured");
            }

            fuzzFullByteSweep(actionId, dlc, statusIds, statusCount);
            if (_stopRequested) break;
        }
        if (_stopRequested) break;
    }

    Serial.println("FUZZ_DONE");
    _running = false;
}


void Fuzzer::clearBlacklist() {
    _blacklistCount = 0;
}


bool Fuzzer::addBlacklist(uint8_t id, uint8_t dlc, const uint8_t* payload) {
    if (_blacklistCount >= MAX_BLACKLIST_ENTRIES) return false;

    BlacklistEntry& entry = _blacklist[_blacklistCount++];
    entry.id = id;
    entry.dlc = dlc;
    memcpy(entry.payload, payload, dlc);
    return true;
}


void Fuzzer::requestStop() {
    _stopRequested = true;
}


bool Fuzzer::isRunning() const {
    return _running;
}


// ─────────────────────────────────────────────────────────────────
//  Stop-Command Check
// ─────────────────────────────────────────────────────────────────

bool Fuzzer::checkForStop() {
    if (_stopRequested) return true;

    if (Serial.available()) {
        String cmd = Serial.readStringUntil('\n');
        cmd.trim();
        if (cmd == "STOP_FUZZ") {
            _stopRequested = true;
            return true;
        }
        if (cmd == "RECAPTURE_BASELINE") {
            _recaptureRequested = true;
            // Don't return true — this is not a stop request
        }
    }
    return false;
}


// ─────────────────────────────────────────────────────────────────
//  Baseline Capture & Comparison
// ─────────────────────────────────────────────────────────────────

void Fuzzer::captureBaseline(const uint8_t* statusIds, uint8_t statusCount) {
    for (uint8_t s = 0; s < statusCount; s++) {
        uint8_t id  = statusIds[s];
        uint8_t dlc = 0;

        _lin->sendHeader(id);
        bool valid = _lin->readResponse(id, _baseline[id], dlc);
        _baselineDLC[id] = valid ? dlc : 0;

        delay(LIN_INTERFRAME_DELAY_MS);
    }
}


bool Fuzzer::compareAndReport(uint8_t actionId, uint8_t actionDLC,
                              const uint8_t* payload,
                              const uint8_t* statusIds,
                              uint8_t statusCount) {
    bool hitDetected = false;

    for (uint8_t s = 0; s < statusCount; s++) {
        uint8_t sid = statusIds[s];
        uint8_t afterData[LIN_MAX_DATA_LEN];
        uint8_t afterDLC = 0;

        _lin->sendHeader(sid);
        bool valid = _lin->readResponse(sid, afterData, afterDLC);

        if (!valid) continue;

        // Compare against baseline
        bool changed = (afterDLC != _baselineDLC[sid]);
        if (!changed) {
            for (uint8_t b = 0; b < afterDLC; b++) {
                if (afterData[b] != _baseline[sid][b]) {
                    changed = true;
                    break;
                }
            }
        }

        if (changed) {
            FuzzHit hit;
            hit.actionId  = actionId;
            hit.dlc       = actionDLC;
            memcpy(hit.payload, payload, actionDLC);
            hit.statusId  = sid;
            hit.statusDlc = _baselineDLC[sid];
            memcpy(hit.beforeData, _baseline[sid], _baselineDLC[sid]);
            memcpy(hit.afterData,  afterData,      afterDLC);

            reportHit(hit);
            hitDetected = true;

            // Update baseline so persistent changes don't re-trigger
            memcpy(_baseline[sid], afterData, afterDLC);
            _baselineDLC[sid] = afterDLC;
        }

        delay(LIN_INTERFRAME_DELAY_MS);
    }

    return hitDetected;
}


// ─────────────────────────────────────────────────────────────────
//  Core Send-and-Check Cycle (Natural Delay Architecture)
// ─────────────────────────────────────────────────────────────────

bool Fuzzer::sendAndCheck(uint8_t actionId, uint8_t dlc,
                          const uint8_t* payload,
                          const uint8_t* statusIds,
                          uint8_t statusCount) {
    reportSending(actionId, dlc, payload);

    // ── Step 1: Inject the fuzz frame (~10ms) ────────────────────
    _lin->sendHeader(actionId);
    _lin->sendResponse(actionId, payload, dlc);

    // ── Step 2: Poll Status IDs (~50-60ms natural delay) ─────────
    // This block creates the hardware settling time for relays/heaters
    // to physically latch, eliminating the need for an explicit delay().
    bool linHit = compareAndReport(actionId, dlc, payload,
                                   statusIds, statusCount);

    // ── Step 3: Active INA260 read (~1ms) ────────────────────────
    bool ampHit = false;
    if (_currentSensor && _currentSensor->isAvailable()) {
        float postMA = _currentSensor->readCurrentMA();

        // Compare against the global idle baseline (absolute threshold).
        // This is consistent with settleAfterAmpHit() which also uses
        // isPhysicalHit().  Catches persistent loads that carry across
        // multiple fuzz frames (e.g. heaters latching ON).
        if (_currentSensor->isPhysicalHit(postMA)) {
            reportAmpHit(actionId, dlc, payload, postMA);
            ampHit = true;

            // Cool down: send all-zeros and wait for current to decay
            settleAfterAmpHit(actionId, dlc, payload,
                              statusIds, statusCount);
        }
    }

    return linHit || ampHit;
}


// ─────────────────────────────────────────────────────────────────
//  Full Byte Sweep
// ─────────────────────────────────────────────────────────────────

bool Fuzzer::isBlacklisted(uint8_t actionId, uint8_t dlc, const uint8_t* payload) const {
    for (uint8_t i = 0; i < _blacklistCount; i++) {
        const BlacklistEntry& entry = _blacklist[i];
        if (entry.id == actionId && entry.dlc == dlc) {
            bool match = true;
            for (uint8_t b = 0; b < dlc; b++) {
                if (entry.payload[b] != payload[b]) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
    }
    return false;
}


void Fuzzer::fuzzFullByteSweep(uint8_t actionId, uint8_t dlc,
                               const uint8_t* statusIds,
                               uint8_t statusCount) {
    uint8_t payload[LIN_MAX_DATA_LEN];

    // For each byte position in the DLC...
    for (uint8_t bytePos = 0; bytePos < dlc; bytePos++) {
        // Reset all bytes to 0x00 before sweeping this position
        memset(payload, 0x00, dlc);

        // Sweep the target byte from 0x00 to 0xFF
        for (uint16_t val = 0; val <= 0xFF; val++) {
            if (checkForStop()) return;

            payload[bytePos] = (uint8_t)val;

            if (isBlacklisted(actionId, dlc, payload)) {
                // Silently skip
                continue;
            }

            sendAndCheck(actionId, dlc, payload, statusIds, statusCount);
            delay(LIN_INTERFRAME_DELAY_MS);
        }
    }
}


// ─────────────────────────────────────────────────────────────────
//  Serial Reporting
// ─────────────────────────────────────────────────────────────────

void Fuzzer::reportSending(uint8_t id, uint8_t dlc, const uint8_t* data) {
    // Format: FUZZ_SENDING:ID=0A,DLC=2,DATA=00_42
    Serial.print("FUZZ_SENDING:ID=");
    if (id < 0x10) Serial.print("0");
    Serial.print(id, HEX);
    Serial.print(",DLC=");
    Serial.print(dlc);
    Serial.print(",DATA=");

    for (uint8_t i = 0; i < dlc; i++) {
        if (i > 0) Serial.print("_");
        if (data[i] < 0x10) Serial.print("0");
        Serial.print(data[i], HEX);
    }
    Serial.println();
}


void Fuzzer::reportHit(const FuzzHit& hit) {
    // Format: FUZZ_HIT:ACTION_ID=0A,DLC=2,DATA=00_42,STATUS_ID=15,BEFORE=00_FF,AFTER=01_FF
    Serial.print("FUZZ_HIT:ACTION_ID=");
    if (hit.actionId < 0x10) Serial.print("0");
    Serial.print(hit.actionId, HEX);

    Serial.print(",DLC=");
    Serial.print(hit.dlc);

    Serial.print(",DATA=");
    for (uint8_t i = 0; i < hit.dlc; i++) {
        if (i > 0) Serial.print("_");
        if (hit.payload[i] < 0x10) Serial.print("0");
        Serial.print(hit.payload[i], HEX);
    }

    Serial.print(",STATUS_ID=");
    if (hit.statusId < 0x10) Serial.print("0");
    Serial.print(hit.statusId, HEX);

    Serial.print(",BEFORE=");
    for (uint8_t i = 0; i < hit.statusDlc; i++) {
        if (i > 0) Serial.print("_");
        if (hit.beforeData[i] < 0x10) Serial.print("0");
        Serial.print(hit.beforeData[i], HEX);
    }

    Serial.print(",AFTER=");
    for (uint8_t i = 0; i < hit.statusDlc; i++) {
        if (i > 0) Serial.print("_");
        if (hit.afterData[i] < 0x10) Serial.print("0");
        Serial.print(hit.afterData[i], HEX);
    }

    Serial.println();
}


void Fuzzer::reportAmpHit(uint8_t actionId, uint8_t dlc,
                          const uint8_t* payload, float currentMA) {
    // Format: FUZZ_HIT_AMP:ACTION_ID=0A,DLC=1,DATA=42,AMP=3.85
    Serial.print("FUZZ_HIT_AMP:ACTION_ID=");
    if (actionId < 0x10) Serial.print("0");
    Serial.print(actionId, HEX);

    Serial.print(",DLC=");
    Serial.print(dlc);

    Serial.print(",DATA=");
    for (uint8_t i = 0; i < dlc; i++) {
        if (i > 0) Serial.print("_");
        if (payload[i] < 0x10) Serial.print("0");
        Serial.print(payload[i], HEX);
    }

    // Convert mA to A with 2 decimal places
    Serial.print(",AMP=");
    Serial.println(currentMA / 1000.0f, 2);
}


// ─────────────────────────────────────────────────────────────────
//  Cooldown: All-Zeros Kill + FATAL_LOCKUP
// ─────────────────────────────────────────────────────────────────

void Fuzzer::settleAfterAmpHit(uint8_t actionId, uint8_t dlc,
                               const uint8_t* payload,
                               const uint8_t* statusIds,
                               uint8_t statusCount) {
    if (!_currentSensor || !_currentSensor->isAvailable()) return;

    Serial.println("INFO:MSG=Amp hit detected — injecting all-zeros cooldown...");

    // ── Stage 1: Immediately inject all-zeros kill frame ─────────
    uint8_t zeroBuf[LIN_MAX_DATA_LEN] = {0};
    _lin->sendHeader(actionId);
    _lin->sendResponse(actionId, zeroBuf, dlc);

    Serial.print("INFO:MSG=Zero Frame injected for ID 0x");
    if (actionId < 0x10) Serial.print("0");
    Serial.print(actionId, HEX);
    Serial.print(" DLC=");
    Serial.println(dlc);

    // ── Stage 2: Poll INA260 every 100ms for up to 5s ───────────
    unsigned long startMs = millis();
    bool settled = false;

    while (!settled && !_stopRequested) {
        unsigned long elapsed = millis() - startMs;

        float mA = _currentSensor->readCurrentMA();
        if (!_currentSensor->isPhysicalHit(mA)) {
            settled = true;
            Serial.print("INFO:MSG=Current settled after ");
            Serial.print(elapsed);
            Serial.println(" ms");
            break;
        }

        // ── Timeout: FATAL_LOCKUP ────────────────────────────────
        if (elapsed >= 5000) {
            // Report the lockup to the GUI with all identifying info
            Serial.print("FATAL_LOCKUP:ID=");
            if (actionId < 0x10) Serial.print("0");
            Serial.print(actionId, HEX);
            Serial.print(",DLC=");
            Serial.print(dlc);
            Serial.print(",DATA=");
            for (uint8_t i = 0; i < dlc; i++) {
                if (i > 0) Serial.print("_");
                if (payload[i] < 0x10) Serial.print("0");
                Serial.print(payload[i], HEX);
            }
            Serial.print(",AMPS=");
            Serial.println(mA / 1000.0f, 2);

            // Halt the fuzzer — GUI handles recovery
            _stopRequested = true;
            return;
        }

        // Check for user abort while settling
        if (checkForStop()) return;

        delay(100);  // Poll every 100 ms
    }
}
