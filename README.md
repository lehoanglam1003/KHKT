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
3. Điền `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN` và `TWILIO_VERIFY_SERVICE_SID` trong `.env` khi chạy local. Trên Render, tạo ba biến này trong **Environment** của service. Đặt `FLASK_SECRET_KEY` ổn định trong môi trường triển khai; không chia sẻ hoặc đưa `.env` lên Git.
4. Chạy ứng dụng bằng `python app.py` trong môi trường ảo đã kích hoạt.

Phân tích ảnh trực quan cần `GEMINI_API_KEY`; có thể đổi model bằng `GEMINI_MODEL` (mặc định `gemini-2.5-flash`). Có thể đặt `OCR_SPACE_API_KEY` để OCR.Space nhận dạng chữ tiếng Việt. Nếu không có Gemini, ứng dụng dùng OCR.Space cùng `GROQ_API_KEY` để đánh giá phần chữ; cách này không phân tích được logo, bố cục hoặc mã QR. Khi bật OCR.Space, ảnh được gửi tới dịch vụ này để trích chữ. Ảnh được thu nhỏ trên trình duyệt trước khi gửi; ảnh gốc tối đa 15 MB và dữ liệu gửi lên máy chủ tối đa 8 MB.

Để bật tra cứu link, bật Google Safe Browsing Lookup API và điền `GOOGLE_SAFE_BROWSING_API_KEY`. Giới hạn key ở phía Google Cloud và chỉ dùng dịch vụ theo điều khoản hiện hành; Safe Browsing Lookup API dành cho mục đích phi thương mại. Khi tra cứu, toàn bộ URL (kể cả tham số truy vấn, nhưng bỏ phần fragment) được gửi tới Google; không tra các link riêng tư chứa mã truy cập. Kết quả không có cảnh báo không chứng minh link an toàn.

Nếu chưa có `GOOGLE_SAFE_BROWSING_API_KEY`, app báo link chưa xác minh thay vì đánh dấu an toàn. Tra cứu cộng đồng số/link vẫn là tín hiệu tham khảo, không phải kết luận chính thức.

Tra cứu số điện thoại dựa trên báo cáo cộng đồng của người dùng đã xác minh OTP. Mỗi tài khoản chỉ có một báo cáo cho mỗi số và có thể gỡ báo cáo; hệ thống chỉ hiển thị tổng hợp, không hiển thị danh tính người báo. Đây không phải cơ sở dữ liệu chính thức và có thể có báo cáo sai.

### Vòng tròn người thân và quyền riêng tư

Số liên hệ SOS được đồng bộ theo tài khoản và mã hóa bằng Fernet với khóa suy ra từ `FLASK_SECRET_KEY`. Hãy đặt khóa ổn định, đủ mạnh và giữ bản sao an toàn; đổi khóa sẽ khiến các số đã mã hóa không thể đọc lại. Người thân phải có tài khoản đã xác minh OTP và tự chấp nhận lời mời. Nhật ký luôn riêng tư theo mặc định; chỉ hồ sơ được chủ tài khoản bật chia sẻ mới xuất hiện với người thân đã liên kết. Gỡ liên kết sẽ thu hồi quyền xem.

### QR và dấu vết cộng đồng

Ảnh được giải mã QR trên trình duyệt bằng `jsQR` tải từ jsDelivr. QR không tự mở; nếu là URL, URL được gửi đến Google Safe Browsing khi tính năng đã cấu hình. Nếu thư viện QR không tải được, ứng dụng báo chưa giải mã thay vì coi ảnh là an toàn. Báo cáo link và nội dung tin nhắn chỉ lưu fingerprint có khóa, không lưu nguyên văn qua luồng báo cáo. Đối chiếu tin nhắn hiện nhận diện nội dung trùng sau chuẩn hóa cơ bản, chưa nhận ra các biến thể được viết lại. Báo cáo cộng đồng chỉ là tín hiệu tham khảo; người dùng có thể gỡ báo cáo của mình.

### Luyện tập và hướng dẫn

Màn hình chính ưu tiên ô kiểm tra; **Tra cứu**, **Luyện tập** và **Nhật ký** được mở riêng từ nút **Công cụ**. Chữ và nút thao tác chính được đặt lớn hơn cho người cao tuổi. Mục **Luyện tập** có thông báo hoàn thành và nút về màn hình chính/luyện lại; điểm tốt nhất và số lần làm được lưu theo tài khoản.

Nhận dạng giọng nói tiếp tục qua các khoảng ngừng ngắn; bấm **Kiểm tra ngay** để chốt nội dung và gửi. OCR.Space thử hai engine khi engine đầu không nhận ra chữ; nếu vẫn thất bại, app hướng dẫn chụp sát, thẳng và đủ sáng, đồng thời không kết luận nội dung an toàn.

Khuyến mãi nạp cước để tham gia quay thưởng không tự nó là dấu hiệu lừa đảo. Với thông báo VinaPhone/VNPT có link thuộc tên miền `vnpt.com.vn` hoặc `vinaphone.com.vn`, không yêu cầu OTP/mật khẩu hay chuyển khoản cá nhân, app tránh tự động gắn cảnh báo đỏ và khuyên người dùng tự xác minh trên ứng dụng chính thức. Quy tắc này không thay thế kiểm tra chiến dịch với nhà mạng.

Trong **Phanh khẩn cấp**, trình duyệt có thể đọc từng bước nếu thiết bị có giọng tiếng Việt. Các tính năng này không tự gọi ngân hàng, người thân hoặc cơ quan chức năng.

Khi phân tích có cảnh báo đỏ/cam, người dùng có thể mở **Phanh khẩn cấp** để chọn điều đã xảy ra, làm checklist theo tình huống và lưu tiến độ vào nhật ký. Nút gọi người thân chỉ mở ứng dụng gọi sau khi người dùng xác nhận. SafeAI không tự khóa giao dịch, không gọi ngân hàng/cơ quan chức năng và không thay thế hướng dẫn chính thức của họ.

Để chia sẻ bản demo tạm thời, có thể bật `PREVIEW_BASIC_AUTH` theo dạng `demo:<mật-khẩu-ngẫu-nhiên-dài>` trước khi khởi chạy. Trình duyệt sẽ yêu cầu tài khoản/mật khẩu trước khi tải trang và gọi API. Chỉ chia sẻ với người tin cậy, dùng dữ liệu giả và tắt biến này sau buổi demo; đây không thay thế xác thực OTP hoặc triển khai production.

Blueprint Render bật Basic Auth cho demo bằng `PREVIEW_BASIC_AUTH_PASSWORD` do Render tự sinh. Tài khoản truy cập là `safeai-preview`; lấy mật khẩu trong **Environment** của web service Render sau khi deploy. Không chia sẻ thông tin này công khai. Cấu hình demo vẫn dùng OTP demo và SQLite trong `/tmp`, vì vậy không dùng cho dữ liệu thật.

Tài khoản mới cần xác minh mã OTP trước khi tạo. Nếu quên mật khẩu, chọn **Quên mật khẩu?**, nhập số điện thoại và mật khẩu mới, sau đó xác minh OTP SMS; mật khẩu chỉ được cập nhật sau khi mã hợp lệ. Phản hồi yêu cầu reset không tiết lộ số điện thoại có tài khoản hay không. Mật khẩu được băm ở máy chủ; không lưu mật khẩu đăng nhập trong trình duyệt. Nhật ký cũ của trình duyệt chỉ được nhập sau khi số điện thoại tương ứng xác minh thành công.

### Triển khai

- Dùng HTTPS và đặt `COOKIE_SECURE=true`.
- Đặt `FLASK_SECRET_KEY` ổn định giống nhau giữa các tiến trình để phiên đăng nhập không mất hiệu lực khi khởi động lại.
- Đặt `DATABASE_PATH` trên ổ đĩa lưu bền vững. SQLite phù hợp khi ứng dụng chạy trên một máy chủ/ổ đĩa dùng chung; nếu chạy nhiều máy chủ độc lập, hãy chuyển sang PostgreSQL.
- Không dùng máy chủ phát triển Flask cho môi trường công khai. Dùng Gunicorn hoặc máy chủ WSGI tương đương.