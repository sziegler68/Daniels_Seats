/**
 * LIN Bus Sniffer Module
 * 
 * Iterates through all 64 LIN frame IDs (0x00–0x3F) sending headers
 * and listening for slave responses.  Reports responsive "Status IDs"
 * with their detected DLC and raw data back to the PC via USB serial.
 */

#ifndef SNIFFER_H
#define SNIFFER_H

#include "lin_bus.h"


/** Result of probing a single LIN frame ID. */
struct SniffResult {
    uint8_t id;
    uint8_t dlc;
    uint8_t data[LIN_MAX_DATA_LEN];
    bool    responsive;   // true if a valid slave response was received
};


class Sniffer {
public:
    Sniffer();

    /** Bind to a LinBus instance (call once after LinBus::begin). */
    void begin(LinBus* lin);

    /**
     * Execute a full header scan across IDs 0x00–0x3F.
     * For each ID, sends a header and listens for a slave response.
     * Reports SNIFF_PROGRESS, STATUS_FOUND, and SNIFF_DONE via Serial.
     * Checks for STOP_SNIFF commands between iterations.
     */
    void scanAll();

    /** Request that an in-progress scan be aborted. */
    void requestStop();

    // ── Accessors ────────────────────────────────────────────────

    /** Get the full results array (LIN_NUM_IDS entries). */
    const SniffResult* getResults() const;

    /** Get the number of responsive IDs found in the last scan. */
    uint8_t getActiveCount() const;

    /** Check if a specific ID was responsive. */
    bool isActive(uint8_t id) const;

    /** Get the result struct for a specific ID. */
    const SniffResult& getResult(uint8_t id) const;

    /** True while a scan is in progress. */
    bool isRunning() const;

private:
    LinBus*      _lin;
    SniffResult  _results[LIN_NUM_IDS];
    uint8_t      _activeCount;
    volatile bool _running;
    volatile bool _stopRequested;

    /** Check USB serial for a STOP_SNIFF command. */
    bool checkForStop();

    /** Send SNIFF_PROGRESS message to PC. */
    void reportProgress(uint8_t currentId);

    /** Send STATUS_FOUND message to PC. */
    void reportFound(const SniffResult& result);

    /** Send SNIFF_DONE message to PC. */
    void reportDone();
};

#endif // SNIFFER_H
