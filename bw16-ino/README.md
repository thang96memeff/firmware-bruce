# HƯỚNG DẪN NẠP FIRMWARE BW16 (RTL8720DN) & SỬA LỖI FLASHLOADER

## 1. Sơ đồ đấu dây Mạch Nạp USB-UART (CH340 / CP2102) -> BW16

> **LƯU Ý CỰC KỲ QUAN TRỌNG:**
> Module BW16 có 2 cổng UART riêng biệt:
> - **CỔNG NẠP FIRMWARE (Log UART - Serial0): PA7 & PA8** (BẮT BUỘC DÙNG CỔNG NÀY ĐỂ NẠP).
> - **CỔNG CHẠY BRUCE (Serial1): PB1 & PB2** (Cổng này CHỈ dùng nối với ESP32 khi chạy, KHÔNG nạp được firmware).

| Mạch nạp USB-UART | Module BW16 (RTL8720DN) | Ghi chú |
| :--- | :--- | :--- |
| **TX** | **PA8 (Log RX)** | Nối chéo TX -> RX |
| **RX** | **PA7 (Log TX)** | Nối chéo RX <- TX |
| **GND** | **GND** | Bắt buộc nối chung Mass |
| **3.3V hoặc 5V** | **3V3 hoặc VIN (5V)** | Khuyên dùng 5V cấp vào VIN để tránh sụt áp |

---

## 2. Cách nạp bằng Ameba Image Tool (Dùng file `.bin` có sẵn)

1. Mở phần mềm **ImageTool.exe**.
2. Cấu hình kết nối:
   - **Chip Select**: `AmebaD (8721D)` hoặc `RTL8720D`.
   - **COM Port**: Chọn đúng cổng COM của mạch nạp USB-UART.
   - **Baudrate**: Chọn **115200** (để tốc độ này ổn định nhất, không bị lỗi bắt tay).
3. Chọn file nạp:
   - **Trường hợp 1: Nạp bình thường**
     - Dòng 1: Tích chọn ô vuông $\rightarrow$ Address điền `0x08006000` $\rightarrow$ Browse chọn file: `km4_image2_all.bin`
   - **Trường hợp 2: Sau khi Erase sạch Flash (Erase All)**
     - Dòng 1: Tích chọn $\rightarrow$ Address: `0x08000000` $\rightarrow$ File: `km0_boot_all.bin`
     - Dòng 2: Tích chọn $\rightarrow$ Address: `0x08006000` $\rightarrow$ File: `km4_image2_all.bin`
4. **ĐƯA CHIP VÀO DOWNLOAD MODE (Thao tác bắt buộc):**
   - **BƯỚC 1**: Nhấn và **GIỮ** nút **Burn** (hoặc dùng dây nối chân `PA8` xuống `GND`).
   - **BƯỚC 2**: Nhấn rồi nhả nút **Reset (RST)** (vẫn đang giữ nút Burn).
   - **BƯỚC 3**: **Thả nút Burn** ra.
5. Bấm nút **Download** trên tool. Đợi chạy xong 100% thì bấm nút **RST** trên BW16 để khởi động lại.

---

## 3. Cách khắc phục lỗi "Err: Flashloader download fail" (99% gặp lỗi này)

Lỗi `Err: Flashloader download fail` xảy ra khi Image Tool mở cổng COM được nhưng chip không phản hồi gói bắt tay RAM loader. Hãy kiểm tra lần lượt:

1. **CHIP CHƯA THỰC SỰ VÀO DOWNLOAD MODE (Nguyên nhân phổ biến nhất):**
   - Rất nhiều người bấm nhầm thứ tự nút.
   - Chuẩn xác: **Giữ nút Burn $\rightarrow$ Bấm nhả RST $\rightarrow$ Thả nút Burn**.
   - Nếu board không có nút Burn: Lấy 1 sợi dây cắm nối thẳng chân `PA8` vào `GND`, bấm nút `RST`, sau đó rút sợi dây ra rồi mới bấm nút Download trên phần mềm.
2. **CẮM NHẦM CHÂN UART:**
   - Bạn có đang cắm vào `PB1` hoặc `PB2` không? Cổng đó không nạp được! Phải cắm vào **PA7** và **PA8**.
   - Kiểm tra chéo dây: `TX` mạch nạp vào `PA8`, `RX` mạch nạp vào `PA7`. Thử đảo chéo lại nếu không chắc chắn.
3. **CHƯA NỐI CHUNG CHÂN GND:**
   - Nếu không có dây GND nối giữa mạch nạp và BW16, tín hiệu UART sẽ bị nhiễu và báo lỗi ngay.
4. **TỐC ĐỘ BAUD QUÁ CAO:**
   - Mặc định tool có thể để 1500000 (1.5 Mbps). Các mạch nạp CH340 rẻ tiền hoặc dây nối dài sẽ bị rớt gói. Hãy đổi Baudrate về **115200**.
5. **NGUỒN CẤP YẾU BỊ SỤT ÁP:**
   - Cổng 3.3V của mạch USB-UART thường chỉ chịu được 50-100mA, trong khi BW16 lúc kích hoạt có thể ăn tới 200mA gây sụt áp Reset ROM.
   - Hãy chuyển jumper trên mạch nạp sang 5V và cắm vào chân `VIN` / `5V` của BW16.

---

## 4. Cách nạp bằng Arduino IDE (Tự động biên dịch & nạp)
1. Cài đặt board AmebaD trong Board Manager (`realtek:AmebaD`).
2. Mở file `bw16-ino.ino`.
3. Chọn board **Ameba RTL8720DN(BW16)**.
4. Nếu muốn xóa sạch data cũ: **Tools** $\rightarrow$ **Erase Flash** $\rightarrow$ **Enable**.
5. Đưa chip vào Download Mode (Giữ Burn $\rightarrow$ Nhấn nhả RST $\rightarrow$ Thả Burn).
6. Nhấn nút **Upload**.

