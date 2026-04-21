/**
 * LIN Bus Protocol Library — Implementation
 * 
 * Break generation uses the manual TX-pin-drive method:
 *   1. Flush pending TX data
 *   2. Disable the USART transmitter (USART0.CTRLB &= ~TXEN)
 *   3. Drive TX pin LOW for 14 bit-times (dominant)
 *   4. Drive TX pin HIGH for 1 bit-time (break delimiter)
 *   5. Re-enable the USART transmitter
 * 
 * This avoids dependencies on ATmega4809 LIN hardware mode, which is
 * not exposed through the Arduino megaAVR core's Serial API.
 */

#include "lin_bus.h"


// ─────────────────────────────────────────────────────────────────
//  Construction & Initialization
// ─────────────────────────────────────────────────────────────────

LinBus::LinBus(HardwareSerial& serial, uint8_t txPin, uint8_t slpPin,
               uint32_t baudRate)
    : _serial(serial)
    , _txPin(txPin)
    , _slpPin(slpPin)
    , _baudRate(baudRate)
    , _enhancedChecksum(true)       // Default to LIN 2.x Enhanced
{
    _bitTimeUs = 1000000UL / _baudRate;   // ~52 µs at 19200
}


void LinBus::begin() {
    _serial.begin(_baudRate);

    // Wake the transceiver if SLP_N is under software control
    if (_slpPin != LIN_SLP_PIN_DISABLED) {
        pinMode(_slpPin, OUTPUT);
        wakeTransceiver();
    }

    delay(50);  // Allow bus to settle after power-up
}


// ─────────────────────────────────────────────────────────────────
//  Transceiver Power Management
// ─────────────────────────────────────────────────────────────────

void LinBus::sleep() {
    if (_slpPin != LIN_SLP_PIN_DISABLED) {
        digitalWrite(_slpPin, LOW);
        delay(5);   // t_gotosleep
    }
}


void LinBus::wakeTransceiver() {
    if (_slpPin != LIN_SLP_PIN_DISABLED) {
        digitalWrite(_slpPin, HIGH);
        delay(15);  // t_gotonorm — wait for Normal Mode transition
    }
}


void LinBus::wakeBusDominant() {
    _serial.flush();

    // Temporarily take manual control of the TX pin
    LIN_SERIAL_USART.CTRLB &= ~USART_TXEN_bm;

    pinMode(_txPin, OUTPUT);
    digitalWrite(_txPin, LOW);               // Dominant
    delayMicroseconds(LIN_WAKEUP_PULSE_US);

    digitalWrite(_txPin, HIGH);              // Release to recessive
    delayMicroseconds(_bitTimeUs * 4);

    LIN_SERIAL_USART.CTRLB |= USART_TXEN_bm;

    delay(150);  // Allow slaves time to wake and initialise
}


// ─────────────────────────────────────────────────────────────────
//  LIN Frame Transmission
// ─────────────────────────────────────────────────────────────────

void LinBus::sendBreak() {
    _serial.flush();  // Wait for any pending TX data to clock out

    // Disable the USART transmitter so we can manually drive the pin
    LIN_SERIAL_USART.CTRLB &= ~USART_TXEN_bm;

    // Drive TX LOW (dominant) for 14 bit-times = ~730 µs at 19200 baud
    pinMode(_txPin, OUTPUT);
    digitalWrite(_txPin, LOW);
    delayMicroseconds(_bitTimeUs * LIN_BREAK_DOMINANT_BITS);

    // Break delimiter: HIGH (recessive) for 1 bit-time = ~52 µs
    digitalWrite(_txPin, HIGH);
    delayMicroseconds(_bitTimeUs * LIN_BREAK_DELIM_BITS);

    // Hand the pin back to the USART
    LIN_SERIAL_USART.CTRLB |= USART_TXEN_bm;
}


void LinBus::sendSync() {
    _serial.write(LIN_SYNC_BYTE);
    _serial.flush();
}


void LinBus::sendPID(uint8_t id) {
    _serial.write(calcParity(id & LIN_MAX_ID));
    _serial.flush();
}


void LinBus::discardEcho() {
    // The TJA1021 echoes all transmitted bytes back on RXD because
    // LIN is a single-wire bus with loopback.  After sending the
    // header (break + sync + PID) we may see up to 3 echoed bytes:
    //   - 0x00 or garbage from the break framing error
    //   - 0x55  (sync echo)
    //   - PID   (PID echo)
    // Wait long enough for all echo bytes to arrive, then drain them.
    delayMicroseconds(1700);   // ~3.3 byte-times at 19200

    while (_serial.available()) {
        _serial.read();
    }
}


void LinBus::sendHeader(uint8_t id) {
    // Drain any stale data sitting in the RX buffer
    while (_serial.available()) {
        _serial.read();
    }

    sendBreak();
    sendSync();
    sendPID(id);

    // Discard the echoed header so readResponse() sees only slave data
    discardEcho();
}


// ─────────────────────────────────────────────────────────────────
//  Response Reading (Slave → Master)
// ─────────────────────────────────────────────────────────────────

bool LinBus::readResponse(uint8_t id, uint8_t* dataBuf,
                          uint8_t& actualDLC, uint16_t timeoutMs) {
    // Buffer for raw incoming bytes: up to 8 data + 1 checksum
    uint8_t rawBuf[LIN_MAX_DATA_LEN + 1];
    uint8_t totalBytes = 0;
    uint8_t pid = calcParity(id & LIN_MAX_ID);

    unsigned long startTime    = millis();
    unsigned long lastByteTime = startTime;

    // Phase 1 — Collect bytes until inter-byte or overall timeout
    while (totalBytes < (LIN_MAX_DATA_LEN + 1)) {
        if (_serial.available()) {
            rawBuf[totalBytes++] = _serial.read();
            lastByteTime = millis();
        } else {
            // If we already have at least one byte, enforce inter-byte gap
            if (totalBytes > 0 &&
                (millis() - lastByteTime) > LIN_INTERBYTE_TIMEOUT_MS) {
                break;
            }
            // Overall frame timeout
            if ((millis() - startTime) > timeoutMs) {
                break;
            }
        }
    }

    if (totalBytes < 2) {
        // Need at minimum 1 data byte + 1 checksum byte
        actualDLC = 0;
        return false;
    }

    // Phase 2 — Validate checksum to determine the correct DLC.
    //           Try the most likely DLC first (totalBytes - 1),
    //           then work downward to account for possible trailing noise.
    for (int tryDLC = totalBytes - 1; tryDLC >= 1; tryDLC--) {
        uint8_t cksum = calcChecksum(pid, rawBuf, tryDLC, _enhancedChecksum);
        if (rawBuf[tryDLC] == cksum) {
            actualDLC = (uint8_t)tryDLC;
            memcpy(dataBuf, rawBuf, tryDLC);
            return true;
        }
    }

    // No valid checksum match — return raw bytes for debugging
    actualDLC = totalBytes;
    memcpy(dataBuf, rawBuf, totalBytes);
    return false;
}


// ─────────────────────────────────────────────────────────────────
//  Response Writing (Master → Slave, for payload injection)
// ─────────────────────────────────────────────────────────────────

void LinBus::sendResponse(uint8_t id, const uint8_t* data, uint8_t len) {
    if (len == 0 || len > LIN_MAX_DATA_LEN) return;

    uint8_t pid   = calcParity(id & LIN_MAX_ID);
    uint8_t cksum = calcChecksum(pid, data, len, _enhancedChecksum);

    _serial.write(data, len);
    _serial.write(cksum);
    _serial.flush();

    // Discard the echo of our transmitted response
    // Each byte is 10 bit-times; wait for (len + 1) bytes + margin
    delayMicroseconds((_bitTimeUs * 10) * (len + 1) + 500);
    while (_serial.available()) {
        _serial.read();
    }
}


// ─────────────────────────────────────────────────────────────────
//  Checksum Mode
// ─────────────────────────────────────────────────────────────────

void LinBus::setChecksumMode(bool enhanced) {
    _enhancedChecksum = enhanced;
}

bool LinBus::isEnhancedChecksum() const {
    return _enhancedChecksum;
}


// ─────────────────────────────────────────────────────────────────
//  Baud Rate Configuration
// ─────────────────────────────────────────────────────────────────

void LinBus::setBaudRate(uint32_t newBaud) {
    _serial.end();
    _baudRate  = newBaud;
    _bitTimeUs = 1000000UL / _baudRate;
    _serial.begin(_baudRate);
    delay(10);  // Allow USART to settle
}

uint32_t LinBus::getBaudRate() const {
    return _baudRate;
}


// ─────────────────────────────────────────────────────────────────
//  Static: Parity Calculation
// ─────────────────────────────────────────────────────────────────

uint8_t LinBus::calcParity(uint8_t id) {
    id &= 0x3F;  // Mask to 6 bits

    uint8_t p0 =  ((id >> 0) ^ (id >> 1) ^ (id >> 2) ^ (id >> 4)) & 0x01;
    uint8_t p1 = ~((id >> 1) ^ (id >> 3) ^ (id >> 4) ^ (id >> 5)) & 0x01;

    return id | (p0 << 6) | (p1 << 7);
}


// ─────────────────────────────────────────────────────────────────
//  Static: Checksum Calculation
// ─────────────────────────────────────────────────────────────────

uint8_t LinBus::calcChecksum(uint8_t pid, const uint8_t* data,
                             uint8_t len, bool enhanced) {
    uint16_t sum = 0;

    // Per LIN spec: diagnostic frame IDs 60 (0x3C) and 61 (0x3D)
    // always use the Classic checksum regardless of the mode setting.
    uint8_t rawId = pid & 0x3F;
    bool useEnhanced = enhanced && (rawId != 0x3C) && (rawId != 0x3D);

    if (useEnhanced) {
        sum = pid;
    }

    for (uint8_t i = 0; i < len; i++) {
        sum += data[i];
        if (sum > 255) {
            sum -= 255;   // Modulo-255 carry handling
        }
    }

    return (uint8_t)(~sum);
}
