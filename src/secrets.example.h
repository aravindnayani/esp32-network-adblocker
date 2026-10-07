#pragma once
// Copy this file to secrets.h. secrets.h is gitignored so your credentials never get committed.
// Everything here is OPTIONAL: the device can be set up entirely from its setup portal.

// Fallback WiFi, used only if none has been saved through the setup portal.
static const char* WIFI_SSID = "YOUR_WIFI_SSID";
static const char* WIFI_PASS = "YOUR_WIFI_PASSWORD";

// Auth for the dashboard's state-changing endpoints (/ban, /addblock, /upload,
// /update, /setupdate, /forgetwifi, ...) and for network OTA (ArduinoOTA).
// The admin password is normally chosen in the setup portal and stored on the
// device; a value set there always wins over WEB_PASS. While the placeholders
// below are unchanged they are ignored (they're public), and with no password
// set anywhere the dashboard's controls and network OTA stay locked.
// OTA_PASS defaults to the admin password when left as the placeholder.
static const char* WEB_USER = "admin";
static const char* WEB_PASS = "CHANGE_ME_WEB_PASSWORD";
static const char* OTA_PASS = "CHANGE_ME_OTA_PASSWORD";
