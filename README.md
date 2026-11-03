# SafeAI

## Đăng nhập OTP và đồng bộ nhật ký

Ứng dụng lưu tài khoản, nhật ký và tiến độ checklist xử lý sự cố trong SQLite trên máy chủ. Cùng một số điện thoại đã xác minh có thể đăng nhập trên nhiều thiết bị để xem và cập nhật chung hồ sơ.

### Cấu hình phát triển

Yêu cầu Python 3.11. Python 3.9 đã hết hỗ trợ.

Tạo môi trường riêng cho dự án bằng Python 3.11:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

1. Tạo một dịch vụ **Verify** trong Twilio Console, bật kênh SMS và kiểm tra quyền gửi đến Việt Nam. Tài khoản dùng thử của Twilio có thể giới hạn số nhận mã.
2. Sao chép `.env.example` thành `.env`.
3. Điền `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN` và `TWILIO_VERIFY_SERVICE_SID` trong `.env`. Đặt `FLASK_SECRET_KEY` thành chuỗi ngẫu nhiên riêng; không chia sẻ hoặc đưa `.env` lên Git.
4. Chạy ứng dụng bằng `python app.py` trong môi trường ảo đã kích hoạt.

Phân tích ảnh cần `GEMINI_API_KEY`; có thể đổi model bằng `GEMINI_MODEL` (mặc định `gemini-2.5-flash`). Ảnh được thu nhỏ trên trình duyệt trước khi gửi; ảnh gốc tối đa 15 MB và dữ liệu gửi lên máy chủ tối đa 8 MB.

Để bật tra cứu link, bật Google Safe Browsing Lookup API và điền `GOOGLE_SAFE_BROWSING_API_KEY`. Giới hạn key ở phía Google Cloud và chỉ dùng dịch vụ theo điều khoản hiện hành; Safe Browsing Lookup API dành cho mục đích phi thương mại. Khi tra cứu, toàn bộ URL (kể cả tham số truy vấn, nhưng bỏ phần fragment) được gửi tới Google; không tra các link riêng tư chứa mã truy cập. Kết quả không có cảnh báo không chứng minh link an toàn.

Tra cứu số điện thoại dựa trên báo cáo cộng đồng của người dùng đã xác minh OTP. Mỗi tài khoản chỉ có một báo cáo cho mỗi số và có thể gỡ báo cáo; hệ thống chỉ hiển thị tổng hợp, không hiển thị danh tính người báo. Đây không phải cơ sở dữ liệu chính thức và có thể có báo cáo sai.

Khi phân tích có cảnh báo đỏ/cam, người dùng có thể mở **Phanh khẩn cấp** để chọn điều đã xảy ra, làm checklist theo tình huống và lưu tiến độ vào nhật ký. Nút gọi người thân chỉ mở ứng dụng gọi sau khi người dùng xác nhận. SafeAI không tự khóa giao dịch, không gọi ngân hàng/cơ quan chức năng và không thay thế hướng dẫn chính thức của họ.

Tài khoản mới cần xác minh mã OTP trước khi tạo. Mật khẩu được băm ở máy chủ; không lưu mật khẩu đăng nhập trong trình duyệt. Nhật ký cũ của trình duyệt chỉ được nhập sau khi số điện thoại tương ứng xác minh thành công.

### Triển khai

- Dùng HTTPS và đặt `COOKIE_SECURE=true`.
- Đặt `FLASK_SECRET_KEY` ổn định giống nhau giữa các tiến trình để phiên đăng nhập không mất hiệu lực khi khởi động lại.
- Đặt `DATABASE_PATH` trên ổ đĩa lưu bền vững. SQLite phù hợp khi ứng dụng chạy trên một máy chủ/ổ đĩa dùng chung; nếu chạy nhiều máy chủ độc lập, hãy chuyển sang PostgreSQL.
- Không dùng máy chủ phát triển Flask cho môi trường công khai. Dùng Gunicorn hoặc máy chủ WSGI tương đương.