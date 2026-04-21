/**
 * LIN Bus Protocol Library for Arduino Nano Every
 * 
 * Implements the LIN 2.x physical and data-link layer for use with
 * a TJA1021 transceiver in Master mode. Handles break generation,
 * parity calculation, and both Enhanced/Classic checksums.
 * 
 * Hardware: Arduino Nano Every (ATmega4809)
 * Transceiver: GODIYMODULES TJA1021
 * Bus Speed: 19,200 baud (configurable)
 * 
 * Serial1 on the Nano Every uses USART0 (PA0=TX1/Pin1, PA1=RX1/Pin0).
 * The SLP_N pin defaults to D2 for transceiver wake control.
 */

#ifndef LIN_BUS_H
#define LIN_BUS_H

#include <Arduino.h>

// ─────────────────────────────────────────────────────────────────
//  LIN Protocol Constants
// ─────────────────────────────────────────────────────────────────

#define LIN_SYNC_BYTE              0x55
#define LIN_MAX_DATA_LEN           8
#define LIN_MAX_ID                 0x3F   // IDs 0–63
#define LIN_NUM_IDS                64

// Break field: 14 dominant bits (LIN spec minimum = 13)
#define LIN_BREAK_DOMINANT_BITS    14
// Break delimiter: 1 recessive bit
#define LIN_BREAK_DELIM_BITS       1

// ─────────────────────────────────────────────────────────────────
//  Timing Constants (milliseconds unless noted)
// ─────────────────────────────────────────────────────────────────

#define LIN_RESPONSE_TIMEOUT_MS    15    // Max wait for first slave byte
#define LIN_INTERBYTE_TIMEOUT_MS   2     // Max gap between consecutive bytes
#define LIN_INTERFRAME_DELAY_MS    5     // Idle time between frames
#define LIN_WAKEUP_PULSE_US        800   // Dominant wake-up pulse (microseconds)

// ─────────────────────────────────────────────────────────────────
//  Hardware Configuration
// ─────────────────────────────────────────────────────────────────

// Set to 255 if TJA1021 SLP_N pin is tied directly to VCC (always on)
#define LIN_SLP_PIN_DISABLED       255

// Arduino Nano Every: Serial1 uses USART0 on the ATmega4809.
// Change this define if porting to a different board/USART mapping.
#define LIN_SERIAL_USART           USART0


// ─────────────────────────────────────────────────────────────────
//  LinBus Class
// ─────────────────────────────────────────────────────────────────

class LinBus {
public:
    /**
     * Construct a LinBus instance.
     * @param serial    Reference to hardware serial port (Serial1)
     * @param txPin     TX pin number for manual break generation
     * @param slpPin    TJA1021 NSLP pin number (LIN_SLP_PIN_DISABLED if tied to VCC)
     * @param baudRate  LIN bus baud rate (default 19200)
     */
    LinBus(HardwareSerial& serial, uint8_t txPin, uint8_t slpPin,
           uint32_t baudRate = 19200);

    /** Initialize the serial port and wake the transceiver. */
    void begin();

    /** Put the transceiver into sleep mode via SLP_N pin. */
    void sleep();

    /** Wake the transceiver from sleep by driving SLP_N HIGH. */
    void wakeTransceiver();

    /** 
     * Send a dominant wake-up pulse on the LIN bus.
     * Used to wake slave nodes from their sleep state.
     */
    void wakeBusDominant();

    /**
     * Send a complete LIN header: Break + Sync (0x55) + PID.
     * Automatically discards the transceiver echo of the header bytes.
     * @param id  Raw 6-bit frame ID (0x00–0x3F)
     */
    void sendHeader(uint8_t id);

    /**
     * Read and validate a slave response after a header has been sent.
     * Uses iterative checksum validation to detect the correct DLC,
     * since LIN headers do not broadcast their data length.
     * 
     * @param id          Frame ID that was sent in the header
     * @param dataBuf     Output buffer (must be >= LIN_MAX_DATA_LEN bytes)
     * @param actualDLC   Output: detected DLC (1–8), or 0 on failure
     * @param timeoutMs   Maximum time to wait for response
     * @return true if a valid response with matching checksum was received
     */
    bool readResponse(uint8_t id, uint8_t* dataBuf, uint8_t& actualDLC,
                      uint16_t timeoutMs = LIN_RESPONSE_TIMEOUT_MS);

    /**
     * Transmit a response (data bytes + checksum) after a header.
     * Used for Master-publish frames, i.e. injecting payloads during fuzzing.
     * @param id    Frame ID
     * @param data  Pointer to data bytes
     * @param len   Number of data bytes (1–8)
     */
    void sendResponse(uint8_t id, const uint8_t* data, uint8_t len);

    /** Set checksum mode: true = Enhanced (LIN 2.x), false = Classic (LIN 1.x) */
    void setChecksumMode(bool enhanced);

    /** Get current checksum mode. */
    bool isEnhancedChecksum() const;

    // ── Static Utility Functions ─────────────────────────────────

    /**
     * Calculate the Protected ID byte from a raw 6-bit ID.
     * Appends two parity bits:
     *   P0 = ID0 ⊕ ID1 ⊕ ID2 ⊕ ID4
     *   P1 = ¬(ID1 ⊕ ID3 ⊕ ID4 ⊕ ID5)
     * @param id  Raw 6-bit frame ID (0x00–0x3F)
     * @return    8-bit Protected ID (PID)
     */
    static uint8_t calcParity(uint8_t id);

    /**
     * Calculate the LIN checksum over a data payload.
     * Enhanced checksum (LIN 2.x) includes the PID in the sum.
     * Classic checksum (LIN 1.x) sums data bytes only.
     * Diagnostic frames (IDs 60–61) always use Classic per the LIN spec.
     * 
     * @param pid       Protected ID byte
     * @param data      Pointer to data bytes
     * @param len       Number of data bytes
     * @param enhanced  true = Enhanced, false = Classic
     * @return          8-bit inverted checksum
     */
    static uint8_t calcChecksum(uint8_t pid, const uint8_t* data,
                                uint8_t len, bool enhanced);

private:
    HardwareSerial& _serial;
    uint8_t  _txPin;
    uint8_t  _slpPin;
    uint32_t _baudRate;
    uint32_t _bitTimeUs;       // Microseconds per bit at _baudRate
    bool     _enhancedChecksum;

    /** Generate a LIN break field by manually driving the TX pin. */
    void sendBreak();

    /** Transmit the sync byte (0x55). */
    void sendSync();

    /** Calculate parity and transmit the Protected ID byte. */
    void sendPID(uint8_t id);

    /** Wait for and discard echoed header bytes from the transceiver. */
    void discardEcho();
};

#endif // LIN_BUS_H
