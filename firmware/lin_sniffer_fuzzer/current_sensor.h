/**
 * INA260 Current & Voltage Sensor Module
 *
 * Wraps the Adafruit_INA260 library to provide:
 *   - Configurable conversion time + averaging (17.6 ms integration window)
 *   - Idle current baseline capture (10-sample average)
 *   - Physical hit detection (current > baseline + threshold)
 *   - Real-time 12V bus voltage reading (VB pad bridged on breakout)
 *
 * The INA260 communicates over I2C (A4/SDA, A5/SCL on the Nano Every)
 * and is wired IN SERIES with the seat module's 12 V power lead.
 *
 * Safety is handled by a physical 15A inline fuse and software polling.
 * No hardware interrupt / ALERT pin is used.
 */

#ifndef CURRENT_SENSOR_H
#define CURRENT_SENSOR_H

#include <Arduino.h>
#include <Adafruit_INA260.h>


// ── Detection Thresholds ─────────────────────────────────────────

/** Delta above idle baseline that qualifies as a "Physical Hit" (mA). */
#define CURRENT_THRESHOLD_MA       500.0f

/** Number of samples used to compute the idle-current baseline. */
#define CURRENT_BASELINE_SAMPLES   10


class CurrentSensor {
public:
    CurrentSensor();

    /**
     * Initialise the INA260 over I2C.
     *
     * @param i2cAddr   I2C address of the INA260 (default 0x40).
     * @return true if the sensor was found and configured.
     */
    bool begin(uint8_t i2cAddr = 0x40);

    /** True after a successful begin(). */
    bool isAvailable() const;

    // ── Measurement ──────────────────────────────────────────────

    /** Read the current right now (mA).  Returns 0 if sensor unavailable. */
    float readCurrentMA();

    /** Read the bus voltage right now (mV).  Returns 0 if unavailable.
     *  Requires the VB solder pad to be bridged on the INA260 breakout
     *  so that VIN+ is routed to the internal bus voltage ADC. */
    float readVoltageMV();

    // ── Baseline ─────────────────────────────────────────────────

    /**
     * Capture the idle-current baseline by averaging
     * CURRENT_BASELINE_SAMPLES consecutive readings.
     * Call this with the seat module powered but idle.
     */
    void captureBaseline();

    /** Return the most-recently captured baseline value (mA). */
    float getBaselineMA() const;

    // ── Hit Detection ────────────────────────────────────────────

    /**
     * Returns true if the supplied current reading exceeds
     * the baseline by CURRENT_THRESHOLD_MA or more.
     */
    bool isPhysicalHit(float currentMA) const;

    /**
     * Convenience: read current and test in one call.
     * Stores the reading in *outMA if non-null.
     */
    bool checkForPhysicalHit(float* outMA = nullptr);

private:
    Adafruit_INA260 _ina;
    bool   _available;
    float  _baselineMA;
};

#endif // CURRENT_SENSOR_H
