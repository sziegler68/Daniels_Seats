/**
 * LIN Bus Fuzzer Module — Implementation
 * 
 * Workflow per Action ID:
 *   1. Take baseline snapshot of all known Status IDs
 *   2. For each payload in the current stage:
 *      a. Report FUZZ_SENDING to PC
 *      b. Send header + response for the Action ID
 *      c. Wait 10 ms for the ECU to react
 *      d. Poll all Status IDs and compare against baseline
 *      e. If any changed: report FUZZ_HIT, update baseline
 *   3. Move to next Action ID
 * 
 * The fuzzer checks for STOP_FUZZ commands between every attempt
 * to remain responsive to user abort requests.
 */

#include "fuzzer.h"


Fuzzer::Fuzzer()
    : _lin(nullptr)
    , _sniffer(nullptr)
    , _running(false)
    , _stopRequested(false)
{
}


void Fuzzer::begin(LinBus* lin, Sniffer* sniffer) {
    _lin     = lin;
    _sniffer = sniffer;
}


// ─────────────────────────────────────────────────────────────────
//  Main Fuzz Entry Point
// ─────────────────────────────────────────────────────────────────

void Fuzzer::startFuzz(const uint8_t* skipIds, uint8_t skipCount) {
    if (!_lin || !_sniffer || _running) return;

    _running       = true;
    _stopRequested = false;

    // ── Build the Status ID list (IDs we monitor for changes) ──
    uint8_t statusIds[LIN_NUM_IDS];
    uint8_t statusCount = 0;

    for (uint8_t i = 0; i <= LIN_MAX_ID; i++) {
        if (_sniffer->isActive(i)) {
            statusIds[statusCount++] = i;
        }
    }

    // ── Build the Action ID list (IDs we will fuzz) ────────────
    uint8_t actionIds[LIN_NUM_IDS];
    uint8_t actionCount = 0;

    for (uint8_t id = 0; id <= LIN_MAX_ID; id++) {
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
    Serial.println(" status IDs");

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

        // Stage 1: Single byte sweep (DLC = 1)
        fuzzSingleByteSweep(actionId, statusIds, statusCount);
        if (_stopRequested) break;

        // Stage 2: Two byte sweep (DLC = 2)
        fuzzTwoByteSweep(actionId, statusIds, statusCount);
        if (_stopRequested) break;

        // Stage 3: Common patterns (DLC = 3–8)
        for (uint8_t dlc = 3; dlc <= LIN_MAX_DATA_LEN; dlc++) {
            fuzzCommonPatterns(actionId, dlc, statusIds, statusCount);
            if (_stopRequested) break;
        }
        if (_stopRequested) break;
    }

    Serial.println("FUZZ_DONE");
    _running = false;
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
//  Core Send-and-Check Cycle
// ─────────────────────────────────────────────────────────────────

bool Fuzzer::sendAndCheck(uint8_t actionId, uint8_t dlc,
                          const uint8_t* payload,
                          const uint8_t* statusIds,
                          uint8_t statusCount) {
    reportSending(actionId, dlc, payload);

    // Inject the fuzz frame
    _lin->sendHeader(actionId);
    _lin->sendResponse(actionId, payload, dlc);

    // Give the ECU time to process the command
    delay(10);

    // Check all Status IDs for state changes
    return compareAndReport(actionId, dlc, payload, statusIds, statusCount);
}


// ─────────────────────────────────────────────────────────────────
//  Stage 1: Single Byte Sweep (DLC = 1)
// ─────────────────────────────────────────────────────────────────

void Fuzzer::fuzzSingleByteSweep(uint8_t actionId,
                                 const uint8_t* statusIds,
                                 uint8_t statusCount) {
    uint8_t payload[1];

    for (uint16_t val = 0; val <= 0xFF; val++) {
        if (checkForStop()) return;

        payload[0] = (uint8_t)val;
        sendAndCheck(actionId, 1, payload, statusIds, statusCount);
        delay(LIN_INTERFRAME_DELAY_MS);
    }
}


// ─────────────────────────────────────────────────────────────────
//  Stage 2: Two Byte Sweep (DLC = 2)
// ─────────────────────────────────────────────────────────────────

void Fuzzer::fuzzTwoByteSweep(uint8_t actionId,
                              const uint8_t* statusIds,
                              uint8_t statusCount) {
    uint8_t payload[2] = {0, 0};

    // Sweep first byte, hold second at 0x00
    for (uint16_t val = 0; val <= 0xFF; val++) {
        if (checkForStop()) return;

        payload[0] = (uint8_t)val;
        payload[1] = 0x00;
        sendAndCheck(actionId, 2, payload, statusIds, statusCount);
        delay(LIN_INTERFRAME_DELAY_MS);
    }

    // Sweep second byte, hold first at 0x00
    for (uint16_t val = 0; val <= 0xFF; val++) {
        if (checkForStop()) return;

        payload[0] = 0x00;
        payload[1] = (uint8_t)val;
        sendAndCheck(actionId, 2, payload, statusIds, statusCount);
        delay(LIN_INTERFRAME_DELAY_MS);
    }
}


// ─────────────────────────────────────────────────────────────────
//  Stage 3: Common Patterns (DLC = 3–8)
// ─────────────────────────────────────────────────────────────────

void Fuzzer::fuzzCommonPatterns(uint8_t actionId, uint8_t dlc,
                                const uint8_t* statusIds,
                                uint8_t statusCount) {
    uint8_t payload[LIN_MAX_DATA_LEN];

    // Pattern 1: All zeros
    memset(payload, 0x00, dlc);
    if (checkForStop()) return;
    sendAndCheck(actionId, dlc, payload, statusIds, statusCount);
    delay(LIN_INTERFRAME_DELAY_MS);

    // Pattern 2: All ones
    memset(payload, 0xFF, dlc);
    if (checkForStop()) return;
    sendAndCheck(actionId, dlc, payload, statusIds, statusCount);
    delay(LIN_INTERFRAME_DELAY_MS);

    // Pattern 3: Incrementing bytes (0x00, 0x01, 0x02, ...)
    for (uint8_t i = 0; i < dlc; i++) payload[i] = i;
    if (checkForStop()) return;
    sendAndCheck(actionId, dlc, payload, statusIds, statusCount);
    delay(LIN_INTERFRAME_DELAY_MS);

    // Pattern 4: Decrementing from 0xFF (0xFF, 0xFE, 0xFD, ...)
    for (uint8_t i = 0; i < dlc; i++) payload[i] = 0xFF - i;
    if (checkForStop()) return;
    sendAndCheck(actionId, dlc, payload, statusIds, statusCount);
    delay(LIN_INTERFRAME_DELAY_MS);

    // Pattern 5: Single bit walk in the first byte (rest zero)
    for (uint8_t bit = 0; bit < 8; bit++) {
        memset(payload, 0x00, dlc);
        payload[0] = (1 << bit);
        if (checkForStop()) return;
        sendAndCheck(actionId, dlc, payload, statusIds, statusCount);
        delay(LIN_INTERFRAME_DELAY_MS);
    }

    // Pattern 6: Alternating nibbles
    memset(payload, 0xAA, dlc);
    if (checkForStop()) return;
    sendAndCheck(actionId, dlc, payload, statusIds, statusCount);
    delay(LIN_INTERFRAME_DELAY_MS);

    memset(payload, 0x55, dlc);
    if (checkForStop()) return;
    sendAndCheck(actionId, dlc, payload, statusIds, statusCount);
    delay(LIN_INTERFRAME_DELAY_MS);

    // Pattern 7: Coarse sweep through first byte (step 16)
    for (uint16_t val = 1; val < 0xFF; val += 16) {
        memset(payload, 0x00, dlc);
        payload[0] = (uint8_t)val;
        if (checkForStop()) return;
        sendAndCheck(actionId, dlc, payload, statusIds, statusCount);
        delay(LIN_INTERFRAME_DELAY_MS);
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
