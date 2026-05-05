# Threat Model - Lab 3

## Thông tin nhóm
- Thành viên 1:  Ngô Gia Bảo - MSSV: 1871020072
- Thành viên 2: Nguyễn Anh Dũng - MSSV: 1871020167

## Assets
Thông điệp (Plaintext): Nội dung bí mật mà người dùng gửi qua mạng.

Khóa DES (Key): Yếu tố then chốt để giải mã dữ liệu.

Vector khởi tạo (IV): Đảm bảo tính ngẫu nhiên của các khối mã hóa trong chế độ CBC.

Log hệ thống: Chứa các vết giao dịch và có thể lộ thông tin nhạy cảm.

Dịch vụ (Port/IP): Khả năng sẵn sàng của cổng 6000 trên máy Receiver.

## Attacker model
Passive Attacker (Nghe lén): Một kẻ tấn công trong cùng mạng nội bộ (LAN/Wi-Fi) sử dụng công cụ như Wireshark để bắt gói tin TCP.

Active Attacker (Sửa đổi): Kẻ có khả năng can thiệp vào đường truyền (Man-in-the-Middle) để thay đổi các byte trong bản mã hoặc header trước khi tới Receiver.

Malicious Client: Kẻ giả mạo Sender để gửi các gói tin rác hoặc gói tin cực lớn nhằm làm treo Receiver.

## Threats
Lộ thông tin bí mật (Information Leakage): Do thiết kế Lab truyền Key và IV dưới dạng plaintext ngay trong Header của gói tin. Bất kỳ ai bắt được gói tin đều có thể giải mã thông điệp dễ dàng.

Tấn công lật bit (Bit-flipping Attack): Vì DES-CBC không có cơ chế xác thực toàn vẹn (Integrity), kẻ tấn công có thể thay đổi một vài byte trong Ciphertext để làm sai lệch nội dung bản rõ sau khi giải mã (ví dụ: đổi số tiền từ 100$ thành 900$).

Tấn công từ chối dịch vụ (DoS via Header): Kẻ tấn công gửi một Header giả với giá trị Length cực lớn (ví dụ: 2GB), khiến Receiver cố gắng cấp phát bộ nhớ khổng lồ dẫn đến treo máy hoặc sập chương trình.

## Mitigations
Mã hóa bất đối xứng (Hybrid Encryption): Sử dụng RSA để mã hóa Key và IV trước khi gửi. Receiver dùng khóa bí mật RSA để mở khóa DES Key.

Sử dụng TLS/SSL: Bọc toàn bộ kết nối Socket trong một kênh truyền TLS để bảo vệ cả Header và Data khỏi việc nghe lén và sửa đổi.

Xác thực toàn vẹn (HMAC): Thêm một mã băm xác thực (Message Authentication Code) vào cuối gói tin để Receiver kiểm tra xem dữ liệu có bị chỉnh sửa trên đường truyền hay không.

## Residual risks
Endpoint Compromise: Nếu máy tính bị nhiễm mã độc, kẻ tấn công có thể đọc trộm Key ngay từ bộ nhớ RAM trước khi nó được mã hóa.

Lộ dữ liệu qua Log: Nếu file log trong thư mục logs/ không được phân quyền cẩn thận, các thành viên khác trong hệ thống vẫn có thể đọc được nội dung nhạy cảm đã lưu.
