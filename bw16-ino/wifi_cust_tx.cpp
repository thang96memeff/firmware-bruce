#include "wifi_cust_tx.h"

/*Disclaimer

This repository is provided "as is", without any warranties, either express or implied, including but not limited to the implied warranties of merchantability, fitness for a particular purpose, or non-infringement. 
In no event shall the author or copyright owner be liable for any claim, damage, or liability arising from, related to, or in connection with the software or the use or exploitation of the software.

The use of this repository and its contents is entirely voluntary and at the user's own risk. The author does not guarantee the accuracy, reliability, or completeness of any information provided in this repository.

By using this repository, you agree to the above terms and confirm that you take full responsibility for complying with any relevant laws or rules.*/

void wifi_tx_raw_frame(void* frame, size_t length) {
  if (rltk_wlan_info == NULL || frame == NULL || length == 0) return;
  
  uint32_t *p_info = *(uint32_t **)(rltk_wlan_info + 0x10);
  if (p_info == NULL) return;
  
  void *ptr = (void *)*p_info;
  if (ptr == NULL) return;

  void *frame_control = alloc_mgtxmitframe((uint8_t *)ptr + 0xae0);
  if (frame_control == NULL) return;

  uint32_t *pxmitbuf_ptr = (uint32_t *)((uint8_t *)frame_control + 0x80);
  if (pxmitbuf_ptr == NULL || *pxmitbuf_ptr == 0) return;

  uint8_t *pkt_buf = (uint8_t *)(*pxmitbuf_ptr);
  update_mgntframe_attrib(ptr, (uint8_t *)frame_control + 8);
  memset(pkt_buf, 0, 0x68);
  uint8_t *frame_data = pkt_buf + 0x28;
  memcpy(frame_data, frame, length);
  *(uint32_t *)((uint8_t *)frame_control + 0x14) = length;
  *(uint32_t *)((uint8_t *)frame_control + 0x18) = length;
  dump_mgntframe(ptr, frame_control);
}

void wifi_tx_deauth_frame(void* src_mac, void* dst_mac, uint16_t reason) {
  DeauthFrame frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  frame.reason = reason;
  wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
}

void wifi_tx_beacon_frame(void* src_mac, void* dst_mac, const char *ssid) {
  BeaconFrame frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  for (size_t i = 0; ssid[i] != '\0'; i++) {
    frame.ssid[i] = ssid[i];
    frame.ssid_length++;
  }
  wifi_tx_raw_frame(&frame, 38 + frame.ssid_length);
}
