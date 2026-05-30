import java.util.*;
import java.util.regex.*;

public class DomXssScanner {

    public static class Finding {
        public final String vulnType;   // "DOM XSS" / "DOM Open Redirect" / "DOM Request Manipulation" / "DOM Cookie Manipulation"
        public final String severity;    // "HIGH" / "MEDIUM"
        public final String sink;
        public final String source;      // null nếu chưa thấy source gần đó
        public final String snippet;
        public final int lineHint;
        public final int sinkStart;
        public final int sinkEnd;

        Finding(String vulnType, String severity, String sink, String source, String snippet, int lineHint, int sinkStart, int sinkEnd) {
            this.vulnType = vulnType;
            this.severity = severity;
            this.sink = sink;
            this.source = source;
            this.snippet = snippet;
            this.lineHint = lineHint;
            this.sinkStart = sinkStart;
            this.sinkEnd = sinkEnd;
        }
    }

    // ===== SOURCE: dữ liệu attacker kiểm soát được (dùng chung cho mọi loại) =====
    private static final Pattern SOURCE = Pattern.compile("location\\.(hash|search|href|pathname)" + "|\\blocation\\b" + "|document\\.(URL|documentURI|referrer|baseURI)" + "|window\\.name" + "|\\bURLSearchParams\\b" + "|\\.(getElementById|querySelector)\\([^)]*\\)\\.value" + "|event\\.data" +                       // postMessage
            "|localStorage\\.|sessionStorage\\.", Pattern.CASE_INSENSITIVE);

    // ===== SINK theo từng loại lỗ hổng =====

    // 1. DOM XSS — sink thực thi script / render HTML
    private static final Pattern SINK_XSS_HIGH = Pattern.compile("\\b(eval|Function|execScript)\\s*\\(" + "|document\\.(write|writeln)\\s*\\(" + "|\\.insertAdjacentHTML\\s*\\(", Pattern.CASE_INSENSITIVE);
    private static final Pattern SINK_XSS_MED = Pattern.compile("\\.(innerHTML|outerHTML)\\s*=" + "|\\.(html|append|prepend|after|before|replaceWith)\\s*\\(" +   // jQuery
            "|\\b(setTimeout|setInterval)\\s*\\(" + "|\\.srcdoc\\s*=", Pattern.CASE_INSENSITIVE);

    // 2. DOM Open Redirect — sink điều hướng
    private static final Pattern SINK_REDIRECT = Pattern.compile("location\\s*=" + "|location\\.(href|replace|assign)\\s*[=(]" + "|window\\.open\\s*\\(" + "|\\.(href)\\s*=" +                      // element.href = ...
            "|document\\.location\\s*=", Pattern.CASE_INSENSITIVE);

    // 3. DOM Request Manipulation — sink xây dựng request
    private static final Pattern SINK_REQUEST = Pattern.compile("\\.open\\s*\\(" +                        // XMLHttpRequest.open
            "|\\bfetch\\s*\\(" + "|\\.(src)\\s*=" +                        // script/img src
            "|\\bnew\\s+WebSocket\\s*\\(" + "|\\bnew\\s+EventSource\\s*\\(", Pattern.CASE_INSENSITIVE);

    // 4. DOM Cookie Manipulation
    private static final Pattern SINK_COOKIE = Pattern.compile("document\\.cookie\\s*=", Pattern.CASE_INSENSITIVE);

    // Gán string literal tĩnh -> bỏ (giảm nhiễu, dùng cho sink dạng gán)
    private static final Pattern STATIC_ASSIGN = Pattern.compile("=\\s*(['\"`])");

    public static List<Finding> scan(String text) {
        List<Finding> out = new ArrayList<>();
        if (text == null || text.isEmpty()) return out;

        scanWith(text, SINK_XSS_HIGH, "DOM XSS", "HIGH", true, out);
        scanWith(text, SINK_XSS_MED, "DOM XSS", "MEDIUM", true, out);
        scanWith(text, SINK_REDIRECT, "DOM Open Redirect", "MEDIUM", true, out);
        scanWith(text, SINK_REQUEST, "DOM Request Manipulation", "MEDIUM", false, out);
        scanWith(text, SINK_COOKIE, "DOM Cookie Manipulation", "MEDIUM", false, out);
        scanWebMessage(text, out);   // <-- thêm
        return out;
    }

    /**
     * @param skipStaticAssign true với sink dạng gán (innerHTML=, location=) để bỏ string tĩnh.
     *                         Với sink dạng gọi hàm (fetch(), open()) thì không áp dụng.
     */
    private static void scanWith(String text, Pattern sinkPat, String vulnType, String baseSev, boolean skipStaticAssign, List<Finding> out) {
        Matcher m = sinkPat.matcher(text);
        while (m.find()) {
            // Bỏ gán string literal tĩnh nếu là sink dạng "= '...'"
            if (skipStaticAssign) {
                int lookEnd = Math.min(text.length(), m.end() + 5);
                String tail = text.substring(m.start(), lookEnd);
                // chỉ bỏ khi sink này là dạng gán và theo sau là nháy mở
                if (tail.contains("=") && STATIC_ASSIGN.matcher(text.substring(m.start(), Math.min(text.length(), m.end() + 5))).find()) {
                    // continue có thể quá tay; chỉ skip nếu ngay sau dấu = là nháy
                    if (Pattern.compile("=\\s*['\"`]").matcher(tail).find()) continue;
                }
            }

            int start = Math.max(0, m.start() - 250);
            int end = Math.min(text.length(), m.end() + 250);
            String window = text.substring(start, end);
            String sinkText = m.group().trim();
            int line = countLines(text, m.start());

            Matcher sm = SOURCE.matcher(window);
            if (sm.find()) {
                // Có source gần sink -> giữ severity gốc
                out.add(new Finding(vulnType, baseSev, sinkText, sm.group(), clean(window), line, m.start(), m.end()));
            }
            // Không có source -> bỏ luôn (trước đây là LOW; giờ để giảm nhiễu thì không báo)
        }
    }

    private static int countLines(String text, int pos) {
        int line = 1;
        for (int i = 0; i < pos && i < text.length(); i++)
            if (text.charAt(i) == '\n') line++;
        return line;
    }

    private static String clean(String s) {
        return s.replaceAll("\\s+", " ").trim();
    }
    // ===== WEB MESSAGE: phát hiện message listener thiếu kiểm tra origin =====

    // Bắt addEventListener("message", handler) hoặc onmessage =
    private static final Pattern MSG_LISTENER = Pattern.compile("addEventListener\\s*\\(\\s*(['\"])message\\1" + "|\\.onmessage\\s*=" + "|window\\.onmessage\\s*=", Pattern.CASE_INSENSITIVE);

    // Kiểm tra origin (nếu CÓ cái này thì an toàn hơn)
    private static final Pattern ORIGIN_CHECK = Pattern.compile("\\.origin\\b" + "|\\.source\\s*===?" +              // e.source === window
            "|\\borigin\\s*===?|===?\\s*origin", Pattern.CASE_INSENSITIVE);

    // Sink nguy hiểm dùng trong handler (gộp XSS + redirect cho web message)
    private static final Pattern MSG_SINK = Pattern.compile("\\.(innerHTML|outerHTML)\\s*=" + "|document\\.(write|writeln)\\s*\\(" + "|\\b(eval|Function)\\s*\\(" + "|\\.insertAdjacentHTML\\s*\\(" + "|location\\s*=|location\\.(href|replace|assign)\\s*[=(]" + "|\\.src\\s*=", Pattern.CASE_INSENSITIVE);

    private static void scanWebMessage(String text, List<Finding> out) {
        Matcher m = MSG_LISTENER.matcher(text);
        while (m.find()) {
            // Lấy khối handler: từ vị trí listener tới ~800 ký tự sau (đủ phủ thân hàm)
            int start = m.start();
            int end = Math.min(text.length(), m.end() + 800);
            String block = text.substring(start, end);

            // Trong khối có sink nguy hiểm không?
            Matcher sinkM = MSG_SINK.matcher(block);
            if (!sinkM.find()) continue;

            // Có kiểm tra origin trong khối không?
            boolean hasOriginCheck = ORIGIN_CHECK.matcher(block).find();

            int line = countLines(text, start);
            String sinkText = sinkM.group().trim();

            // Thiếu origin check + có sink -> nguy cơ cao
            String sev = hasOriginCheck ? "MEDIUM" : "HIGH";
            String note = hasOriginCheck ? "message listener (CÓ kiểm tra origin — vẫn nên review)" : "message listener THIẾU kiểm tra origin";

            out.add(new Finding("DOM XSS via Web Message", sev, sinkText, note, clean(block.length() > 400 ? block.substring(0, 400) : block), line, start, m.end()));
        }
    }
}