# Data Dictionary - Hệ thống Insider Threat & Blockchain Audit

Tài liệu này định nghĩa chi tiết cấu trúc bảng, kiểu dữ liệu, tính chất Nullable và ý nghĩa nghiệp vụ của từng trường thông tin trong cơ sở dữ liệu giám sát an ninh hệ thống.

---

## 1. Phân hệ Thông tin Thực thể & Thiết bị

### # Table: users
Description: Store employee information.

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| **id** | UUID | No | Khóa chính. Định danh duy nhất cho từng nhân sự. |
| **username** | VARCHAR(100) | No | Mã định danh hoặc tên đăng nhập của nhân viên (Unique). |
| **email** | VARCHAR(255) | Yes | Địa chỉ thư điện tử công vụ của nhân sự. |
| **department** | VARCHAR(100) | Yes | Phòng ban trực thuộc (ví dụ: HR, IT, Finance, Sales...). |
| **role** | VARCHAR(100) | Yes | Chức vụ hoặc vị trí công tác đảm nhiệm. |
| **created_at** | TIMESTAMP | No | Thời điểm tài khoản nhân sự được khởi tạo trên hệ thống. |
| **updated_at** | TIMESTAMP | No | Thời điểm cập nhật thông tin nhân sự gần nhất. |

### # Table: devices
Description: Lưu trữ thông tin các thiết bị đầu cuối do nhân viên sử dụng. Một nhân viên có thể sở hữu hoặc sử dụng nhiều thiết bị.

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| **id** | UUID | No | Khóa chính. Định danh duy nhất cho từng thiết bị phần cứng. |
| **user_id** | UUID | Yes | Khóa ngoại tham chiếu đến bảng `users.id`. |
| **hostname** | VARCHAR(255) | Yes | Tên máy tính định danh trong mạng domain nội bộ. |
| **device_type** | VARCHAR(50) | Yes | Loại thiết bị phần cứng (e.g., Laptop, Desktop, Workstation). |
| **first_seen** | TIMESTAMP | Yes | Thời điểm hệ thống ghi nhận thiết bị này xuất hiện lần đầu tiên. |
| **last_seen** | TIMESTAMP | Yes | Thời điểm gần nhất thiết bị có hoạt động gửi telemetry về hệ thống. |

---

## 2. Phân hệ Nhật ký Hoạt động (Telemetry Logs)

### # Table: login_events
Description: Ghi lại nhật ký các sự kiện đăng nhập của người dùng trên các thiết bị.

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| **id** | UUID | No | Khóa chính. Định danh duy nhất cho mỗi sự kiện đăng nhập. |
| **user_id** | UUID | Yes | Khóa ngoại tham chiếu đến bảng `users.id`. |
| **device_id** | UUID | Yes | Khóa ngoại tham chiếu đến bảng `devices.id`. |
| **login_time** | TIMESTAMP | Yes | Thời gian thực hiện hành vi đăng nhập. |
| **source_ip** | VARCHAR(100) | Yes | Địa chỉ IP nguồn phát ra yêu cầu đăng nhập. |
| **success** | BOOLEAN | Yes | Kết quả đăng nhập (`TRUE` là thành công, `FALSE` là thất bại). |
| **created_at** | TIMESTAMP | Yes | Thời điểm bản ghi được ghi nhận vào cơ sở dữ liệu. |

### # Table: file_events
Description: Giám sát toàn bộ các tương tác, thao túng tệp tin nhạy cảm của người dùng trên thiết bị.

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| **id** | UUID | No | Khóa chính. Định danh duy nhất cho mỗi hành vi tương tác tệp tin. |
| **user_id** | UUID | Yes | Khóa ngoại tham chiếu đến bảng `users.id`. |
| **device_id** | UUID | Yes | Khóa ngoại tham chiếu đến bảng `devices.id`. |
| **filename** | TEXT | Yes | Tên của tệp tin được tác động. |
| **file_path** | TEXT | Yes | Đường dẫn tuyệt đối của tệp tin trên hệ thống file. |
| **file_size** | BIGINT | Yes | Dung lượng của tệp tin tính theo đơn vị Bytes. |
| **action** | VARCHAR(50) | Yes | Hành vi chuẩn hóa: `OPEN`, `COPY`, `DELETE`, `MODIFY`, `UPLOAD`, `DOWNLOAD`. |
| **classification** | VARCHAR(50) | Yes | Phân loại bảo mật dữ liệu: `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`. |
| **event_time** | TIMESTAMP | Yes | Thời điểm chính xác hành vi tương tác tệp tin diễn ra. |

### # Table: usb_events
Description: Ghi lại lịch sử kết nối và tương tác với các thiết bị lưu trữ ngoại vi (USB/Ổ cứng di động).

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| **id** | UUID | No | Khóa chính. Định danh duy nhất cho mỗi sự kiện USB. |
| **user_id** | UUID | Yes | Khóa ngoại tham chiếu đến bảng `users.id`. |
| **device_id** | UUID | Yes | Khóa ngoại tham chiếu đến bảng `devices.id`. |
| **usb_serial** | VARCHAR(255) | Yes | Số sê-ri phần cứng phần cứng của thiết bị ngoại vi. |
| **action** | VARCHAR(50) | Yes | Loại hành vi kết nối: `CONNECT`, `DISCONNECT`, `COPY`. |
| **event_time** | TIMESTAMP | Yes | Thời điểm chính xác sự kiện USB xảy ra. |

### # Table: email_events
Description: Theo dõi luồng thư điện tử gửi và nhận của nhân sự, phục vụ việc giám sát rò rỉ thông tin.

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| **id** | UUID | No | Khóa chính. Định danh duy nhất cho từng sự kiện email. |
| **user_id** | UUID | Yes | Khóa ngoại tham chiếu đến bảng `users.id`. |
| **sender** | VARCHAR(255) | Yes | Địa chỉ email của người gửi. |
| **recipient** | VARCHAR(255) | Yes | Địa chỉ email của người nhận thư. |
| **subject** | TEXT | Yes | Tiêu đề của email. |
| **attachment_name** | TEXT | Yes | Tên của tệp tin đính kèm (nếu có). |
| **attachment_size** | BIGINT | Yes | Dung lượng tệp tin đính kèm tính theo đơn vị Bytes. |
| **is_external** | BOOLEAN | Yes | Cờ đánh dấu email gửi/nhận với domain bên ngoài tổ chức (`TRUE`/`FALSE`). |
| **event_time** | TIMESTAMP | Yes | Thời điểm hệ thống mail server xử lý email. |

---

## 3. Phân hệ Phân tích & Đánh giá Rủi ro (UBA)

### # Table: behavior_profiles
Description: Lưu trữ hồ sơ hành vi nền (baseline) được tính toán động từ phân hệ học máy phục vụ việc phát hiện bất thường.

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| **id** | UUID | No | Khóa chính. Định danh hồ sơ hành vi. |
| **user_id** | UUID | No | Khóa ngoại tham chiếu đến `users.id` (Ràng buộc duy nhất 1:1). |
| **avg_login_hour** | NUMERIC | Yes | Giờ đăng nhập trung bình hàng ngày (ví dụ: 8.4 tương đương 08:24 sáng). |
| **avg_files_per_day** | NUMERIC | Yes | Số lượng tương tác file trung bình được thực hiện trong một ngày. |
| **avg_usb_per_week** | NUMERIC | Yes | Tần suất kết nối thiết bị USB trung bình trong một tuần. |
| **avg_external_emails**| NUMERIC | Yes | Số lượng email gửi tới domain ngoài trung bình một ngày. |
| **risk_baseline** | NUMERIC | Yes | Điểm rủi ro hành vi nền tảng được thuật toán ML thiết lập ban đầu. |
| **last_updated** | TIMESTAMP | Yes | Thời điểm cập nhật lại các chỉ số trung bình của hồ sơ. |

### # Table: risk_scores
Description: Ghi lại lịch sử biến động điểm rủi ro của từng người dùng theo các mốc thời gian đánh giá định kỳ.

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| **id** | UUID | No | Khóa chính. Định danh bản ghi điểm rủi ro. |
| **user_id** | UUID | Yes | Khóa ngoại tham chiếu đến bảng `users.id`. |
| **score** | NUMERIC | Yes | Giá trị điểm số rủi ro cụ thể tính toán tại mốc thời gian chỉ định. |
| **level** | VARCHAR(20) | Yes | Phân loại mức độ nguy hiểm: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. |
| **calculated_at** | TIMESTAMP | Yes | Thời điểm hệ thống chạy engine tính toán ra điểm số này. |

---

## 4. Phân hệ Điều tra Sự cố, Blockchain & Báo cáo AI

### # Table: incidents
Description: Quản lý các sự cố an ninh thông tin hoặc dấu hiệu vi phạm chính sách do hệ thống cảnh báo hoặc điều tra viên thiết lập.

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| **id** | UUID | No | Khóa chính. Định danh duy nhất cho vụ việc sự cố. |
| **incident_code** | VARCHAR(50) | Yes | Mã sự cố được chuẩn hóa phục vụ tra cứu nhanh (ví dụ: INC-2026-001). |
| **user_id** | UUID | Yes | Khóa ngoại tham chiếu đối tượng nghi vấn `users.id`. |
| **title** | TEXT | Yes | Tiêu đề tóm tắt ngắn gọn về sự cố xảy ra. |
| **description** | TEXT | Yes | Mô tả diễn biến chi tiết các hành vi nghi vấn của vụ việc. |
| **severity** | VARCHAR(20) | Yes | Mức độ nghiêm trọng của sự cố: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. |
| **status** | VARCHAR(20) | Yes | Trạng thái xử lý vụ việc: `OPEN`, `INVESTIGATING`, `RESOLVED`, `CLOSED`. |
| **risk_score** | NUMERIC | Yes | Điểm số rủi ro tổng hợp riêng trong ngữ cảnh của sự cố này. |
| **created_at** | TIMESTAMP | Yes | Thời điểm sự cố được khởi tạo trên hệ thống giám sát. |

### # Table: evidences
Description: Kho lưu trữ thông tin bằng chứng số được đóng băng từ các telemetry log để phục vụ điều tra pháp lý.

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| **id** | UUID | No | Khóa chính. Định danh bằng chứng số. |
| **incident_id** | UUID | Yes | Khóa ngoại liên kết với vụ việc lớn nằm trong bảng `incidents.id`. |
| **evidence_type** | VARCHAR(50) | Yes | Phân loại nguồn chứng cứ gốc: `LOGIN`, `FILE`, `USB`, `EMAIL`. |
| **source_event_id**| UUID | Yes | ID trỏ thẳng đến bản ghi gốc trong bảng telemetry tương ứng (Khóa ngoại động). |
| **evidence_hash** | TEXT | Yes | Chuỗi băm mật mã (SHA-256) của toàn bộ dữ liệu bằng chứng để đối chiếu toàn vẹn. |
| **created_at** | TIMESTAMP | Yes | Thời điểm bằng chứng số được trích xuất và thực hiện chốt dữ liệu. |

### # Table: blockchain_blocks
Description: Sổ cái lưu trữ thông tin khối của Blockchain để bảo toàn tính toàn vẹn tuyệt đối của chứng cứ số, chống giả mạo từ quản trị viên hệ thống.

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| **id** | UUID | No | Khóa chính. Định danh duy nhất cho khối dữ liệu. |
| **block_index** | INTEGER | Yes | Vị trí/Chiều cao của khối trong chuỗi Blockchain (Index bắt đầu từ 0). |
| **incident_id** | UUID | Yes | Khóa ngoại liên kết với sự cố mục tiêu `incidents.id`. |
| **evidence_hash** | TEXT | Yes | Giá trị mã băm bằng chứng số được lấy từ bảng `evidences.evidence_hash`. |
| **previous_hash** | TEXT | Yes | Giá trị mã băm của khối đứng ngay trước nó trong chuỗi liên kết. |
| **block_hash** | TEXT | Yes | Giá trị mã băm hợp lệ của chính khối hiện tại để tạo tính liên kết bảo mật. |
| **created_at** | TIMESTAMP | Yes | Thời điểm khối được khai thác hoặc chốt ghi nhận vào sổ cái (Notarized). |

### # Table: investigation_reports
Description: Lưu trữ các kết luận, báo cáo phân tích tự động tổng hợp bởi mô hình trí tuệ nhân tạo (AI Investigator).

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| **id** | UUID | No | Khóa chính. Định danh duy nhất cho báo cáo điều tra. |
| **incident_id** | UUID | Yes | Khóa ngoại liên kết trực tiếp với sự cố `incidents.id`. |
| **generated_by** | VARCHAR(50) | Yes | Tên phiên bản của mô hình AI/Agent thực hiện (e.g., 'AI_INVESTIGATOR_V1.5'). |
| **summary** | TEXT | Yes | Nội dung báo cáo tổng hợp chuyên sâu, phân tích chuỗi hành vi và kết luận. |
| **confidence_score**| NUMERIC | Yes | Điểm số thể hiện mức độ tin cậy của AI đối với kết luận đưa ra (Từ 0.00 đến 100.00). |
| **created_at** | TIMESTAMP | Yes | Thời điểm AI tổng hợp và xuất bản báo cáo thành công. |