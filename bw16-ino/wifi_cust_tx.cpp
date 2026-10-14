#include "wifi_cust_tx.h"

/*
 * Transmits a raw 802.11 frame with a given length.
 * The frame must be valid and have a sequence number of 0 as it will be set automatically.
 * The frame check sequence is added automatically and must not be included in the length.
 * @param frame A pointer to the raw frame
 * @param size The size of the frame
*/
void wifi_tx_raw_frame(void* frame, size_t length) {
  void *ptr = (void *)**(uint32_t **)(rltk_wlan_info + 0x10);
  void *frame_control = alloc_mgtxmitframe(ptr + 0xae0);

  if (frame_control != 0) {
    update_mgntframe_attrib(ptr, frame_control + 8);
    memset((void *)*(uint32_t *)(frame_control + 0x80), 0, 0x68);
    uint8_t *frame_data = (uint8_t *)*(uint32_t *)(frame_control + 0x80) + 0x28;
    memcpy(frame_data, frame, length);
    *(uint32_t *)(frame_control + 0x14) = length;
    *(uint32_t *)(frame_control + 0x18) = length;
    dump_mgntframe(ptr, frame_control);
  }
}

/*
 * Transmits a 802.11 deauth frame on the active channel
 * @param src_mac An array of bytes containing the mac address of the sender. The array has to be 6 bytes in size
 * @param dst_mac An array of bytes containing the destination mac address or FF:FF:FF:FF:FF:FF to broadcast the deauth
 * @param reason A reason code according to the 802.11 spec. Optional 
*/
void wifi_tx_deauth_frame(void* src_mac, void* dst_mac, uint16_t reason) {
  DeauthFrame frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  frame.reason = reason;
  wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
}

/*
 * Transmits a 802.11 disassociation frame on the active channel
 * Frame Control: 0xA0 (Disassociation)
*/
void wifi_tx_disassoc_frame(void* src_mac, void* dst_mac, uint16_t reason) {
  DeauthFrame frame;
  frame.frame_control = 0xA0; // Disassociation subtype
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  frame.reason = reason;
  wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
}

/*
 * Transmits a 802.11 WPA3 SAE Commit Authentication frame
 * Triggers scalar multiplication calculation on the AP's crypto engine
*/
void wifi_tx_sae_commit_frame(void* bssid, void* src_mac) {
  uint8_t frame[128];
  memset(frame, 0, sizeof(frame));

  // 802.11 Auth frame header
  frame[0] = 0xB0; // Authentication frame subtype
  frame[1] = 0x00;
  frame[2] = 0x00; // Duration
  frame[3] = 0x00;
  memcpy(&frame[4], bssid, 6);    // Addr1: BSSID (Destination)
  memcpy(&frame[10], src_mac, 6); // Addr2: Client MAC (Source)
  memcpy(&frame[16], bssid, 6);   // Addr3: BSSID
  frame[22] = 0x00; // Seq
  frame[23] = 0x00;

  // SAE Commit Body
  frame[24] = 0x03; // Auth Algorithm = 3 (SAE)
  frame[25] = 0x00;
  frame[26] = 0x01; // Auth Transaction Seq = 1 (Commit)
  frame[27] = 0x00;
  frame[28] = 0x00; // Status Code = 0 (Success)
  frame[29] = 0x00;
  frame[30] = 0x13; // Group = 19 (0x0013, NIST P-256)
  frame[31] = 0x00;

  // Random Scalar (32 bytes) + Random Element (64 bytes)
  for (int i = 32; i < 128; i++) {
    frame[i] = (uint8_t)rand();
  }

  wifi_tx_raw_frame(frame, sizeof(frame));
}

/*
 * Transmits a very basic 802.11 beacon with the given ssid on the active channel
 * @param src_mac An array of bytes containing the mac address of the sender. The array has to be 6 bytes in size
 * @param dst_mac An array of bytes containing the destination mac address or FF:FF:FF:FF:FF:FF to broadcast the beacon
 * @param ssid '\0' terminated array of characters representing the SSID
*/
void wifi_tx_beacon_frame(void* src_mac, void* dst_mac, const char *ssid) {
  BeaconFrame frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  for (int i = 0; ssid[i] != '\0'; i++) {
    frame.ssid[i] = ssid[i];
    frame.ssid_length++;
  }
  wifi_tx_raw_frame(&frame, 38 + frame.ssid_length);
}