/**
 * INA260 Current & Voltage Sensor Module — Implementation
 *
 * Configuration applied in begin():
 *   Conversion Time : 1.1 ms  (INA260_TIME_1_1_ms)
 *   Averaging Count : 16      (INA260_COUNT_16)
 *   Integration Time: 1.1 ms × 16 = 17.6 ms
 *
 * This 17.6 ms window filters PWM noise from seat heaters while
 * fitting comfortably inside the fuzzer's timing budget.
 *
 * Safety is handled by a physical 15A inline fuse and software
 * polling — no hardware interrupt / ALERT pin is used.
 */

#include "current_sensor.h"
#include <Wire.h>


CurrentSensor::CurrentSensor()
    : _available(false)
    , _baselineMA(0.0f)
{
}


bool CurrentSensor::begin(uint8_t i2cAddr) {
    // Initialise I2C and probe for the INA260
    if (!_ina.begin(i2cAddr, &Wire)) {
        _available = false;
        return false;
    }
    _available = true;

    // ── Measurement configuration ────────────────────────────────
    // 1.1 ms conversion × 16-sample averaging = 17.6 ms integration
    _ina.setCurrentConversionTime(INA260_TIME_1_1_ms);
    _ina.setVoltageConversionTime(INA260_TIME_1_1_ms);
    _ina.setAveragingCount(INA260_COUNT_16);

    return true;
}


bool CurrentSensor::isAvailable() const {
    return _available;
}


// ─────────────────────────────────────────────────────────────────
//  Measurement
// ─────────────────────────────────────────────────────────────────

float CurrentSensor::readCurrentMA() {
    if (!_available) return 0.0f;
    return _ina.readCurrent();   // Returns milliamps (float)
}


float CurrentSensor::readVoltageMV() {
    if (!_available) return 0.0f;
    return _ina.readBusVoltage();  // Returns millivolts (float)
}


// ─────────────────────────────────────────────────────────────────
//  Baseline
// ─────────────────────────────────────────────────────────────────

void CurrentSensor::captureBaseline() {
    if (!_available) {
        _baselineMA = 0.0f;
        return;
    }

    float sum = 0.0f;
    for (uint8_t i = 0; i < CURRENT_BASELINE_SAMPLES; i++) {
        sum += _ina.readCurrent();
        delay(20);   // Space readings ~20 ms apart for stability
    }
    _baselineMA = sum / (float)CURRENT_BASELINE_SAMPLES;
}


float CurrentSensor::getBaselineMA() const {
    return _baselineMA;
}


// ─────────────────────────────────────────────────────────────────
//  Hit Detection
// ─────────────────────────────────────────────────────────────────

bool CurrentSensor::isPhysicalHit(float currentMA) const {
    return currentMA > (_baselineMA + CURRENT_THRESHOLD_MA);
}


bool CurrentSensor::checkForPhysicalHit(float* outMA) {
    float mA = readCurrentMA();
    if (outMA) *outMA = mA;
    return isPhysicalHit(mA);
}
