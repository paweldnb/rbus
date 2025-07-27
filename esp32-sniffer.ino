#include <WiFi.h>
#include <ArduinoOTA.h>
#include "driver/uart.h"
// ==== KONFIGURACJA Wi-Fi ====
const char* ssid = "XXXXXXXX";
const char* password = "XXXXXXXXXX";
WiFiServer telnetServer(23);
WiFiClient telnetClient;

HardwareSerial& uart = Serial2;
const int ledPin = 2;

void setup() {
  Serial.begin(115200);
  uart.begin(9600, SERIAL_8N1, 16, 17);  // RX=GPIO16, TX=GPIO17
  uart_set_line_inverse(UART_NUM_2, UART_SIGNAL_RXD_INV);  // Invert RX (data input)

  pinMode(ledPin, OUTPUT);
  digitalWrite(ledPin, HIGH);

  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nConnected to Wi-Fi");
  Serial.println(WiFi.localIP());

  telnetServer.begin();
  telnetServer.setNoDelay(true);

  ArduinoOTA.setHostname("esp32-sniffer");
  ArduinoOTA.setPassword("XXXXXXXXX");
  ArduinoOTA.begin();
}

void loop() {
  ArduinoOTA.handle();

  if (telnetServer.hasClient()) {
    if (!telnetClient || !telnetClient.connected()) {
      if (telnetClient) telnetClient.stop();
      telnetClient = telnetServer.accept();
    } else {
      WiFiClient rejectClient = telnetServer.accept();
      rejectClient.stop();
    }
  }

  while (uart.available()) {
    byte b = uart.read();

    char hexBuf[4];
    sprintf(hexBuf, "%02X ", b);

    Serial.print(hexBuf);

    if (telnetClient && telnetClient.connected()) {
      telnetClient.print(hexBuf);
    }

    digitalWrite(ledPin, !digitalRead(ledPin));  // simple blink
    yield();  // watchdog-friendly
  }
}
