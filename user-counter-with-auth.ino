#include <Adafruit_GFX.h>
#include "Adafruit_LEDBackpack.h"
#include <time.h>
#include <base64.h>
#include <ArduinoJson.h>
#include <ESP8266WiFi.h>
#include <WiFiClientSecure.h>

#include "arduino_secrets.h"

// #define DEBUG true

// WiFi Setup
char ssid[] = SECRET_SSID;
char pass[] = SECRET_PASS;

// Auth0 Application Settings
String client_id = SECRET_CLIENT_ID;
String client_secret = SECRET_CLIENT_SECRET;
String audience = SECRET_AUDIENCE;
String scope = "offline_access";

// Tokens
String access_token = "";
String refresh_token = "";

// SSL Setup
const int httpsPort = 443;

const char* authHost = SECRET_DOMAIN;
char auth_fingerprint[] PROGMEM = SECRET_AUTH_FINGERPRINT;

const char* apiHost = SECRET_API_DOMAIN;
char api_fingerprint[] PROGMEM = SECRET_API_FINGERPRINT;

// Device flow
String device_grant_type = "urn:ietf:params:oauth:grant-type:device_code";
String refresh_grant_type = "refresh_token";
String code_endpoint = "/oauth/device/code";
String token_endpoint = "/oauth/token";
String verification_uri;
String device_code;

// Declare states as global variables
static const int ERROR_STATE = -1;
static const int AUTH_REQUIRED = 0;
static const int POLL_FOR_TOKEN = 1;
static const int GET_USER_COUNT = 2;
static const int REFRESH_TOKEN = 3;

// Set global variable attributes.
static int CURRENT_STATE = AUTH_REQUIRED;

// Declare 7-seg displays and user count
Adafruit_7segment highDigitDisplay = Adafruit_7segment(); // left-hand display - displays digits greater than 9,999
Adafruit_7segment lowDigitDisplay = Adafruit_7segment(); // right-hand display - displays digits less than 10,000
int userCount;

// Send a secure request
String request(const char* server, char* fingerprint, String header, String data = "") {
  String response = "";

  // Use WiFiClientSecure class to create TLS connection
  WiFiClientSecure client;
  
  client.setFingerprint(fingerprint);
  client.setTimeout(15000);
  delay(1000);

  #ifdef DEBUG
    Serial.print("Connecting to: "); Serial.println(server);
    Serial.println();
  #endif

  if (client.connect(server, httpsPort)) {
    String request = (data == "") ? header : header + data;
    client.print(request);

    while (client.connected()) {
      if(client.find("HTTP/1.1 ")) {
        String status_code = client.readStringUntil('\r');
        #ifdef DEBUG
          Serial.print("Status code: "); Serial.println(status_code);
        #endif
        if (status_code != "200 OK") {
          #ifdef DEBUG
            Serial.println("There was an error");
          #endif
          response = status_code;
          break;
        } else {
          if (client.find("\r\n\r\n")) {
            #ifdef DEBUG
              Serial.println("Data:");
            #endif
          }
          String line = client.readStringUntil('\r');
          #ifdef DEBUG
            Serial.println(line);
          #endif
          response += line;   
        }
      }
    }
  } else {
    Serial.println("Error: Could not connect");
    CURRENT_STATE = ERROR_STATE;
  }

  return response;
}

// Send POST to /oauth/device/code to get the device code and prompt user to activate device
void requestCode() {
  String postData = "";
  postData += "&client_id=" + client_id;
  postData += "&audience=" + audience;
  postData += "&scope=" + scope;
  postData += "&grant_type=" + device_grant_type;
  String postHeader = "";
  postHeader += ("POST " + code_endpoint + " HTTP/1.0\r\n");
  postHeader += ("Host: " + String(authHost) + ":" + String(httpsPort) + "\r\n");
  postHeader += ("Connection: close\r\n");
  postHeader += ("Content-Type: application/x-www-form-urlencoded\r\n");
  postHeader += ("Content-Length: ");
  postHeader += (postData.length());
  postHeader += ("\r\n\r\n");
  String response = request(authHost, auth_fingerprint, postHeader, postData);
  DynamicJsonDocument doc(1024);
  deserializeJson(doc, response);
  device_code = doc["device_code"].as<String>();
  verification_uri = doc["verification_uri_complete"].as<String>();
  Serial.println("Please activate this device: " + verification_uri);
  Serial.println();
  CURRENT_STATE = POLL_FOR_TOKEN;
}

// Send POST to /oauth/token to get the Access Token.
// When `refresh` is true, use Refresh Token to get a new Access Token
void requestToken(bool refresh = false) {
  String postData = "";
  if (refresh) {
    postData += "&client_id=" + client_id;
    postData += "&client_secret=" + client_secret;
    postData += "&refresh_token=" + refresh_token;
    postData += "&grant_type=" + refresh_grant_type;
  } else {
    postData += "&client_id=" + client_id;
    postData += "&device_code=" + device_code;
    postData += "&grant_type=" + device_grant_type;
  }

  String postHeader = "";
  postHeader += ("POST " + token_endpoint + " HTTP/1.0\r\n");
  postHeader += ("Host: " + String(authHost) + ":" + String(httpsPort) + "\r\n");
  postHeader += ("Connection: close\r\n");
  postHeader += ("Content-Type: application/x-www-form-urlencoded\r\n");
  postHeader += ("Content-Length: ");
  postHeader += (postData.length());
  postHeader += ("\r\n\r\n");
  String response = request(authHost, auth_fingerprint, postHeader, postData);
  #ifdef DEBUG
    Serial.println(response);
  #endif
  DynamicJsonDocument doc(1024);
  deserializeJson(doc, response);

  if (doc["refresh_token"]) {
    refresh_token = doc["refresh_token"].as<String>();
  }
  if (doc["access_token"]) {
    access_token = doc["access_token"].as<String>();
    CURRENT_STATE = GET_USER_COUNT;
  }
}

void showUserCount() {
  uint16_t highDigits = userCount / 10000; // Value on left (high digits) display
  uint16_t lowDigits = userCount % 10000; // Value on right (low digits) display

  highDigitDisplay.print(highDigits, DEC);
  lowDigitDisplay.print(lowDigits, DEC);

  // Place zeroes in front of the lowDigit value if userCount is greater than 10,000
  if (highDigits) {
    if (lowDigits < 1000) {
      lowDigitDisplay.writeDigitNum(0, 0);
    }
    if (lowDigits < 100) {
      lowDigitDisplay.writeDigitNum(1, 0);
    }
    if (lowDigits < 10) {
      lowDigitDisplay.writeDigitNum(3, 0);
    }
  } else {
    highDigitDisplay.clear();
  }

  highDigitDisplay.writeDisplay();
  lowDigitDisplay.writeDisplay();
}

// Send GET to User Count API
void displayUserCount() {
  String getHeader = "";
  getHeader += ("GET / HTTP/1.0\r\n");
  getHeader += ("Host: " + String(apiHost) + ":" + String(httpsPort) + "\r\n");
  getHeader += ("Connection: close\r\n");
  getHeader += ("Authorization: Bearer " + access_token + "\r\n");
  getHeader += ("Content-Type: application/json; charset=UTF-8\r\n");
  getHeader += ("\r\n\r\n");
  String response = request(apiHost, api_fingerprint, getHeader);
  if (response == "401 Unauthorized") {
    CURRENT_STATE = REFRESH_TOKEN;
    return;
  }
  #ifdef DEBUG
    Serial.println(response);
  #endif
  DynamicJsonDocument doc(1024);
  deserializeJson(doc, response);
  userCount = doc["userCount"];
  showUserCount();
}

// Set up Wi-Fi connection
void setupWifi() {
  Serial.print("Connecting to WiFi");
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, pass);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println();
  Serial.print("WiFi connected. "); Serial.print("IP address: "); Serial.println(WiFi.localIP());
  Serial.println();
}

// Initialize 7-segment displays
void initDisplays() {
  highDigitDisplay.begin(0x71);
  lowDigitDisplay.begin(0x70);
}

void setup() {
  Serial.begin(115200); Serial.println();
  initDisplays();
  setupWifi();
}

void loop() {
  switch (CURRENT_STATE) {
    case AUTH_REQUIRED:
      // Send POST to /oauth/device/code and print the returned `user code` to the Serial Monitor and set value for device_code
      requestCode();
      break;
    case POLL_FOR_TOKEN:
      // Send POST to /oauth/token using the device code. If an Access Token is returned, the user has activated the device
      requestToken();
      break;
    case GET_USER_COUNT:
      // Use Access Token to get the user count and display it
      displayUserCount();
      break;
    case REFRESH_TOKEN:
      // Use refresh token to get a new Access Token
      requestToken(true);
      break;
    default:
      Serial.println("ERROR");
      break;
  }
  delay(3000);
}
