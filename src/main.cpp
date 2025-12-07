// src/main.cpp (only for ESP32 build)
//
// This file is *not* used for Linux builds.

#include <Arduino.h>

// Forward declaration from modbus_honeypot.cpp
void startModbusHoneypotTask();

void setup() {
    Serial.begin(115200);
    // TODO: connect WiFi here (ssid, pass)

    // Start Modbus honeypot in a FreeRTOS task
    startModbusHoneypotTask();
}

void loop() {
    delay(1000);
}
