#include "wifi_cust_tx.h"

/*Disclaimer

This repository is provided "as is", without any warranties, either express or implied, including but not limited to the implied warranties of merchantability, fitness for a particular purpose, or non-infringement. 
In no event shall the author or copyright owner be liable for any claim, damage, or liability arising from, related to, or in connection with the software or the use or exploitation of the software.

The use of this repository and its contents is entirely voluntary and at the user's own risk. The author does not guarantee the accuracy, reliability, or completeness of any information provided in this repository.

By using this repository, you agree to the above terms and confirm that you take full responsibility for complying with any relevant laws or rules.*/

// RTL8720DN AmebaD SRAM: 0x10000000 - 0x10080000 (512KB)
// Nếu con trỏ nằm ngoài vùng này → địa chỉ rác → HardFault ngay khi dereference
static inline bool is_valid_ram(const void *p) {
  uint32_t addr = (uint32_t)p;
  return (addr >= 0x10000000UL && addr < 0x10080000UL);
}

// Biến đếm lỗi TX để debug (đọc qua Serial nếu cần)
volatile uint32_t tx_fail_count = 0;

int wifi_tx_raw_frame(void* frame, size_t length) {
  if (frame == NULL || length == 0 || length > 500) return -1;
  if (rltk_wlan_info == NULL || !is_valid_ram(rltk_wlan_info)) { tx_fail_count++; return -2; }
  
  // Bước 1: Lấy con trỏ wlan_info → netif adapter
  uint32_t *p_info = *(uint32_t **)(rltk_wlan_info + 0x10);
  if (p_info == NULL || !is_valid_ram(p_info)) { tx_fail_count++; return -3; }
  
  // Bước 2: Lấy con trỏ adapter private data
  void *ptr = (void *)*p_info;
  if (ptr == NULL || !is_valid_ram(ptr)) { tx_fail_count++; return -4; }

  // Bước 3: Cấp phát management transmit frame từ pool
  // Nếu pool hết (gửi quá nhanh) → trả NULL → bỏ qua thay vì crash
  void *frame_control = alloc_mgtxmitframe((uint8_t *)ptr + 0xae0);
  if (frame_control == NULL) { tx_fail_count++; return -5; }
  if (!is_valid_ram(frame_control)) { tx_fail_count++; return -6; }

  // Bước 4: Lấy con trỏ pxmitbuf→pbuf (DMA packet buffer)
  // ĐÂY LÀ CHỖ GÂY CRASH: nếu pbuf = 0x00000000, memset sẽ xóa Vector Table ARM
  uint32_t *pxmitbuf_ptr = (uint32_t *)((uint8_t *)frame_control + 0x80);
  if (!is_valid_ram(pxmitbuf_ptr)) { tx_fail_count++; return -7; }
  
  uint8_t *pkt_buf = (uint8_t *)(*pxmitbuf_ptr);
  if (pkt_buf == NULL || !is_valid_ram(pkt_buf)) { tx_fail_count++; return -8; }
  
  // An toàn: tất cả con trỏ đã được validate → tiến hành ghi frame
  update_mgntframe_attrib(ptr, (uint8_t *)frame_control + 8);
  memset(pkt_buf, 0, 0x68);
  memcpy(pkt_buf + 0x28, frame, length);
  *(uint32_t *)((uint8_t *)frame_control + 0x14) = length;
  *(uint32_t *)((uint8_t *)frame_control + 0x18) = length;
  dump_mgntframe(ptr, frame_control);
  return 0; // Thành công
}

void wifi_tx_deauth_frame(void* src_mac, void* dst_mac, uint16_t reason) {
  DeauthFrame frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  frame.reason = reason;
  wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
}

void wifi_tx_disassoc_frame(void* src_mac, void* dst_mac, uint16_t reason) {
  DisassocFrame frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  frame.reason = reason;
  wifi_tx_raw_frame(&frame, sizeof(DisassocFrame));
}

void wifi_tx_beacon_frame(void* src_mac, void* dst_mac, const char *ssid) {
  BeaconFrame frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  for (size_t i = 0; ssid[i] != '\0' && i < 32; i++) {
    frame.ssid[i] = ssid[i];
    frame.ssid_length++;
  }
  wifi_tx_raw_frame(&frame, 38 + frame.ssid_length);
}
