/**
 * LIN Bus Fuzzer Module
 * 
 * Systematically injects payloads into unused (non-responsive) LIN
 * frame IDs and monitors known Status IDs for state changes.
 * Only scans IDs 0–59 (0x00–0x3B); IDs 60–63 are reserved per
 * LIN 2.x spec and excluded from automated fuzzing.
 * 
 * Fuzzing Strategy — Full Byte Sweep:
 *   For each Action ID and each candidate DLC (1–8):
 *     1. Hold all payload bytes at 0x00
 *     2. Target Byte 0, sweep 0x00–0xFF (256 values)
 *     3. Reset Byte 0 to 0x00, target Byte 1, sweep 0x00–0xFF
 *     4. Repeat for each byte position in the DLC
 *   Total payloads per Action ID per DLC = 256 × DLC
 *   A 30 ms delay is inserted between each injected payload and
 *   the subsequent Status ID poll to allow ECU reaction time.
 *
 * Dual Hit Detection:
 *   - "Orange Hit" (LIN):  Status ID byte change detected
 *   - "Purple Hit" (AMP):  Current spike > baseline + 500 mA (INA260)
 *   Both checks run after every injected payload.
 */

#ifndef FUZZER_H
#define FUZZER_H

#include "lin_bus.h"
#include "sniffer.h"

// Forward declaration — avoids circular include
class CurrentSensor;


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

    /** Bind to a LinBus, Sniffer, and (optional) CurrentSensor instance. */
    void begin(LinBus* lin, Sniffer* sniffer, CurrentSensor* cs = nullptr);

    /**
     * Start the fuzzing process.
     * @param skipIds    Array of IDs to exclude from fuzzing
     * @param skipCount  Number of IDs in the skipIds array
     * 
     * Automatically excludes known Status IDs (from sniffer results)
     * and uses them as the monitoring set for change detection.
     * Only scans IDs 0–59 (0x00–0x3B).
     */
    void startFuzz(const uint8_t* skipIds, uint8_t skipCount);

    /** Request that an in-progress fuzz be aborted. */
    void requestStop();

    /** True while fuzzing is in progress. */
    bool isRunning() const;

private:
    LinBus*         _lin;
    Sniffer*        _sniffer;
    CurrentSensor*  _currentSensor;
    volatile bool _running;
    volatile bool _stopRequested;
    volatile bool _recaptureRequested;
    volatile bool _resumeRequested;

    // Baseline status data for before/after comparison
    uint8_t _baseline[LIN_NUM_IDS][LIN_MAX_DATA_LEN];
    uint8_t _baselineDLC[LIN_NUM_IDS];

    /** Non-blocking check for STOP_FUZZ or RECAPTURE_BASELINE commands. */
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

    /** Send a FUZZ_HIT message to PC (LIN status change — orange). */
    void reportHit(const FuzzHit& hit);

    /** Send a FUZZ_HIT_AMP message to PC (current spike — purple). */
    void reportAmpHit(uint8_t actionId, uint8_t dlc,
                      const uint8_t* payload, float currentMA);

    // ── Payload Generation ───────────────────────────────────────

    /** Send and check a single payload, handling the full cycle. */
    bool sendAndCheck(uint8_t actionId, uint8_t dlc, const uint8_t* payload,
                      const uint8_t* statusIds, uint8_t statusCount);

    /**
     * Full Byte Sweep: for the given DLC, iterate through each byte
     * position (0 to dlc-1), sweeping that byte from 0x00 to 0xFF
     * while all other bytes are held at 0x00.
     */
    void fuzzFullByteSweep(uint8_t actionId, uint8_t dlc,
                           const uint8_t* statusIds, uint8_t statusCount);

    // ── Thermal Settling ─────────────────────────────────────────

    /**
     * After an amp hit, wait for current to settle before continuing.
     * Three-stage escalation:
     *   Stage 1 (0–3s):  Poll INA260, wait for watchdog/natural decay
     *   Stage 2 (3s):    Inject zero-frame active kill
     *   Stage 3 (5s):    Halt fuzzer, require manual reset
     */
    void settleAfterAmpHit(uint8_t actionId, uint8_t dlc,
                           const uint8_t* payload,
                           const uint8_t* statusIds, uint8_t statusCount);

    /** Block until the user sends RESUME_FUZZ via serial. */
    void waitForResume();
};

#endif // FUZZER_H
