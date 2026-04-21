/**
 * LIN Bus Fuzzer Module
 * 
 * Systematically injects payloads into unused (non-responsive) LIN
 * frame IDs and monitors known Status IDs for state changes.
 * 
 * Fuzzing Strategy (staged to avoid exhaustive 2^64 enumeration):
 *   Stage 1 — DLC=1: Full single-byte sweep (0x00–0xFF)
 *   Stage 2 — DLC=2: Sweep first byte, then second byte independently
 *   Stage 3 — DLC=3–8: Common patterns (zeros, ones, bit-walks, ramps)
 */

#ifndef FUZZER_H
#define FUZZER_H

#include "lin_bus.h"
#include "sniffer.h"


/** Record of a successful fuzz hit: an Action ID that triggered a change. */
struct FuzzHit {
    uint8_t actionId;
    uint8_t dlc;
    uint8_t payload[LIN_MAX_DATA_LEN];
    uint8_t statusId;
    uint8_t beforeData[LIN_MAX_DATA_LEN];
    uint8_t afterData[LIN_MAX_DATA_LEN];
    uint8_t statusDlc;
};


class Fuzzer {
public:
    Fuzzer();

    /** Bind to a LinBus and Sniffer instance. */
    void begin(LinBus* lin, Sniffer* sniffer);

    /**
     * Start the fuzzing process.
     * @param skipIds    Array of IDs to exclude from fuzzing
     * @param skipCount  Number of IDs in the skipIds array
     * 
     * Automatically excludes known Status IDs (from sniffer results)
     * and uses them as the monitoring set for change detection.
     */
    void startFuzz(const uint8_t* skipIds, uint8_t skipCount);

    /** Request that an in-progress fuzz be aborted. */
    void requestStop();

    /** True while fuzzing is in progress. */
    bool isRunning() const;

private:
    LinBus*   _lin;
    Sniffer*  _sniffer;
    volatile bool _running;
    volatile bool _stopRequested;

    // Baseline status data for before/after comparison
    uint8_t _baseline[LIN_NUM_IDS][LIN_MAX_DATA_LEN];
    uint8_t _baselineDLC[LIN_NUM_IDS];

    /** Non-blocking check for STOP_FUZZ command on USB serial. */
    bool checkForStop();

    /** Snapshot all known Status IDs into the baseline arrays. */
    void captureBaseline(const uint8_t* statusIds, uint8_t statusCount);

    /**
     * After sending a fuzz payload, poll all Status IDs and compare
     * against the baseline.  Reports FUZZ_HIT for any that changed.
     * Updates the baseline to the new state so persistent changes
     * don't re-trigger on every subsequent attempt.
     * @return true if any Status ID changed
     */
    bool compareAndReport(uint8_t actionId, uint8_t actionDLC,
                          const uint8_t* payload,
                          const uint8_t* statusIds, uint8_t statusCount);

    /** Send a FUZZ_SENDING message to PC. */
    void reportSending(uint8_t id, uint8_t dlc, const uint8_t* data);

    /** Send a FUZZ_HIT message to PC. */
    void reportHit(const FuzzHit& hit);

    // ── Payload Generation Stages ────────────────────────────────

    /** Send and check a single payload, handling the full cycle. */
    bool sendAndCheck(uint8_t actionId, uint8_t dlc, const uint8_t* payload,
                      const uint8_t* statusIds, uint8_t statusCount);

    /** Stage 1: DLC=1, all 256 single-byte values. */
    void fuzzSingleByteSweep(uint8_t actionId,
                             const uint8_t* statusIds, uint8_t statusCount);

    /** Stage 2: DLC=2, sweep each byte position independently. */
    void fuzzTwoByteSweep(uint8_t actionId,
                          const uint8_t* statusIds, uint8_t statusCount);

    /** Stage 3: Common patterns for a given DLC (3–8). */
    void fuzzCommonPatterns(uint8_t actionId, uint8_t dlc,
                            const uint8_t* statusIds, uint8_t statusCount);
};

#endif // FUZZER_H
