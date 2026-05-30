# Burp Extension: API JavaScript Extractor

## Yêu cầu

- Người dùng **phải thêm phạm vi (Scope) vào Burp**
- Extension **chỉ hoạt động** nếu URL nằm trong scope đã cấu hình.

### 1. Trích xuất API/Endpoint từ JS & HTML
- Passive scan mọi response trong scope (HTML, JS, JSON, text).
- Bắt endpoint từ nhiều kiểu viết: `fetch`, `axios`, `XMLHttpRequest`, `jQuery AJAX`, `Angular HttpClient`, `template literal`, `HTML attribute`, `config object`, `WebSocket/EventSource`.
- Gom tham số (query params) thấy được cho mỗi endpoint.
- Dedup theo path, lưu CSV tự động, đối chiếu SiteMap (đánh dấu endpoint đã/chưa được request).
- Lọc, tìm kiếm, export danh sách API và export folder trong scope.

### 2. Phát hiện nghi vấn DOM-based XSS
- Quét source → sink trên cùng nội dung JS/HTML.
- Phân loại mức độ (HIGH/MEDIUM), bỏ qua thư viện bên thứ ba và string tĩnh để giảm nhiễu.
- Báo cáo trực tiếp vào Burp Issues (confidence: Tentative), kèm marker bôi vàng vị trí sink trong response.

> Lưu ý: phần DOM XSS dùng heuristic tĩnh (regex), chỉ gợi ý điểm cần review thủ công, không phải xác nhận lỗ hổng.
