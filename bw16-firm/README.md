# BW16 / RTL8720DN Firmware & Flashing Tools (AmebaD 3.1.5)

Thư mục này chứa đầy đủ các file nhị phân (firmware binaries) và các công cụ để nạp cho module Wi-Fi Dual-Band BW16 (RTL8720DN) hoạt động tương thích 100% với Bruce OS & Flipper Zero.

---

## 1. Danh sách file và địa chỉ nạp trên Flash (Realtek AmebaD Image Tool)

| File | Offset Address | Chức năng |
| :--- | :--- | :--- |
| `km0_boot_all.bin` | `0x08000000` | Bootloader cho nhân KM0 (Cortex-M0) |
| `km4_boot_all.bin` | `0x08004000` | Bootloader cho nhân KM4 (Cortex-M4) |
| `km0_km4_image2.bin` | `0x08006000` | **Firmware ứng dụng chính** (đã tối ưu AmebaD 3.1.5, burst-mode 50ms) |

---

## 2. Hướng dẫn nạp

### Cách 1: Nạp bằng Realtek AmebaD Image Tool (GUI)
1. Mở file `ImageTool.exe`.
2. Chọn **Chip Select**: `AmebaD`.
3. Chọn cổng **COM** và **Baudrate** (khuyên dùng `1500000` hoặc `115200`).
4. Tích chọn 3 dòng và trỏ đường dẫn đến:
   * `km0_boot_all.bin` -> `0x08000000`
   * `km4_boot_all.bin` -> `0x08004000`
   * `km0_km4_image2.bin` -> `0x08006000`
5. Đưa BW16 vào chế độ Download:
   * Nhấn giữ nút **Burn** (hoặc chân `PA0` nối `GND`).
   * Nhấn rồi nhả nút **RST**.
   * Thả nút **Burn**.
6. Bấm nút **Download** trên Image Tool.

### Cách 2: Nạp nhanh bằng dòng lệnh (`upload_image_tool_windows.exe`)
Mở PowerShell tại thư mục này và chạy:
```powershell
.\upload_image_tool_windows.exe . COM5 AmebaD Disable Disable 1500000
```
*(Thay `COM5` bằng cổng COM thực tế của BW16)*.

### Cách 3: Nạp qua Web Flasher
Dùng file đơn `firmware.bin` (chính là bản `km0_km4_image2.bin`) để nạp qua các trình nạp Web Serial.

---

## 3. Sơ đồ nối dây với ESP32 (Bruce OS)
* **ESP32 TX** (ví dụ GPIO 21, 4...) $\rightarrow$ **BW16 RX1** (Chân PB2 / D5)
* **ESP32 RX** (ví dụ GPIO 22, 5...) $\leftarrow$ **BW16 TX1** (Chân PB1 / D4)
* **GND** $\leftrightarrow$ **GND**
* **3V3/5V** $\leftrightarrow$ **VCC**
