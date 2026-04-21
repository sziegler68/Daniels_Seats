/**
 * LIN Bus Sniffer Module — Implementation
 * 
 * Scan Strategy:
 *   For each ID from 0x00 to 0x3F:
 *     1. Send a LIN header (Break + Sync + PID)
 *     2. Listen for a slave response with a 15 ms timeout
 *     3. If response received, validate checksum and detect DLC
 *     4. Report the result to the PC via formatted serial strings
 *     5. Wait LIN_INTERFRAME_DELAY_MS before the next header
 * 
 * The scan periodically checks for STOP_SNIFF commands on the USB
 * serial port so the user can abort a scan in progress.
 */

#include "sniffer.h"


Sniffer::Sniffer()
    : _lin(nullptr)
    , _activeCount(0)
    , _running(false)
    , _stopRequested(false)
{
    memset(_results, 0, sizeof(_results));
}


void Sniffer::begin(LinBus* lin) {
    _lin = lin;
}


void Sniffer::scanAll() {
    if (!_lin || _running) return;

    _running       = true;
    _stopRequested = false;
    _activeCount   = 0;
    memset(_results, 0, sizeof(_results));

    Serial.println("INFO:MSG=Starting header scan (IDs 0x00-0x3F)...");

    for (uint8_t id = 0; id <= LIN_MAX_ID; id++) {
        // Check for user-requested abort
        if (checkForStop()) {
            Serial.println("INFO:MSG=Sniff aborted by user");
            break;
        }

        reportProgress(id);

        // Send header and listen for slave response
        _lin->sendHeader(id);

        uint8_t dataBuf[LIN_MAX_DATA_LEN];
        uint8_t dlc = 0;
        bool valid = _lin->readResponse(id, dataBuf, dlc);

        if (valid && dlc > 0) {
            _results[id].id         = id;
            _results[id].dlc        = dlc;
            _results[id].responsive = true;
            memcpy(_results[id].data, dataBuf, dlc);

            _activeCount++;
            reportFound(_results[id]);
        }

        delay(LIN_INTERFRAME_DELAY_MS);
    }

    reportDone();
    _running = false;
}


void Sniffer::requestStop() {
    _stopRequested = true;
}


// ─────────────────────────────────────────────────────────────────
//  Accessors
// ─────────────────────────────────────────────────────────────────

const SniffResult* Sniffer::getResults() const {
    return _results;
}

uint8_t Sniffer::getActiveCount() const {
    return _activeCount;
}

bool Sniffer::isActive(uint8_t id) const {
    if (id > LIN_MAX_ID) return false;
    return _results[id].responsive;
}

const SniffResult& Sniffer::getResult(uint8_t id) const {
    return _results[id];
}

bool Sniffer::isRunning() const {
    return _running;
}


// ─────────────────────────────────────────────────────────────────
//  Private Helpers
// ─────────────────────────────────────────────────────────────────

bool Sniffer::checkForStop() {
    if (_stopRequested) return true;

    // Non-blocking check for a STOP_SNIFF command from the PC
    if (Serial.available()) {
        String cmd = Serial.readStringUntil('\n');
        cmd.trim();
        if (cmd == "STOP_SNIFF") {
            _stopRequested = true;
            return true;
        }
    }
    return false;
}


void Sniffer::reportProgress(uint8_t currentId) {
    // Format: SNIFF_PROGRESS:ID=0A,TOTAL=64
    Serial.print("SNIFF_PROGRESS:ID=");
    if (currentId < 0x10) Serial.print("0");
    Serial.print(currentId, HEX);
    Serial.println(",TOTAL=64");
}


void Sniffer::reportFound(const SniffResult& result) {
    // Format: STATUS_FOUND:ID=15,DLC=4,DATA=00_FF_00_12
    Serial.print("STATUS_FOUND:ID=");
    if (result.id < 0x10) Serial.print("0");
    Serial.print(result.id, HEX);

    Serial.print(",DLC=");
    Serial.print(result.dlc);

    Serial.print(",DATA=");
    for (uint8_t i = 0; i < result.dlc; i++) {
        if (i > 0) Serial.print("_");
        if (result.data[i] < 0x10) Serial.print("0");
        Serial.print(result.data[i], HEX);
    }
    Serial.println();
}


void Sniffer::reportDone() {
    // Format: SNIFF_DONE:COUNT=7
    Serial.print("SNIFF_DONE:COUNT=");
    Serial.println(_activeCount);
}
