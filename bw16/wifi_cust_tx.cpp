#include "wifi_cust_tx.h"

// RTL8720DN AmebaD SRAM: 0x10000000 - 0x10080000 (512KB)
// Nếu con trỏ nằm ngoài vùng RAM hợp lệ -> HardFault ngay lập tức
static inline bool is_valid_ram(const void *p) {
  uint32_t addr = (uint32_t)p;
  return (addr >= 0x10000000UL && addr < 0x10080000UL);
}

int wifi_tx_raw_frame(void* frame, size_t length) {
  if (frame == NULL || length == 0 || length > 500) return -1;
  if (rltk_wlan_info == NULL || !is_valid_ram(rltk_wlan_info)) return -2;
  
  // 1. Con trỏ adapter
  uint32_t *p_info = *(uint32_t **)(rltk_wlan_info + 0x10);
  if (p_info == NULL || !is_valid_ram(p_info)) return -3;
  
  void *ptr = (void *)*p_info;
  if (ptr == NULL || !is_valid_ram(ptr)) return -4;

  // 2. Cấp phát management frame descriptor
  void *frame_control = alloc_mgtxmitframe((uint8_t *)ptr + 0xae0);
  if (frame_control == NULL || !is_valid_ram(frame_control)) return -5;

  // 3. Con trỏ pxmitbuf (DMA packet buffer)
  uint32_t *pxmitbuf_ptr = (uint32_t *)((uint8_t *)frame_control + 0x80);
  if (pxmitbuf_ptr == NULL || !is_valid_ram(pxmitbuf_ptr) || *pxmitbuf_ptr == 0) return -6;

  uint8_t *pkt_buf = (uint8_t *)(*pxmitbuf_ptr);
  if (pkt_buf == NULL || !is_valid_ram(pkt_buf)) return -7;

  // 4. An toàn: Ghi frame vào bộ đệm và chuyển cho DMA phát
  update_mgntframe_attrib(ptr, (uint8_t *)frame_control + 8);
  memset(pkt_buf, 0, 0x68);
  uint8_t *frame_data = pkt_buf + 0x28;
  memcpy(frame_data, frame, length);
  *(uint32_t *)((uint8_t *)frame_control + 0x14) = length;
  *(uint32_t *)((uint8_t *)frame_control + 0x18) = length;
  dump_mgntframe(ptr, frame_control);
  return 0;
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
