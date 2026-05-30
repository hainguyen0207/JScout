import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.Map;

import javax.swing.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.api.montoya.core.Marker;
import burp.api.montoya.core.Range;

public class MyHttpHandler implements HttpHandler {
    private final Logging logging;
    private final APITab tab;
    private final MontoyaApi api;

    private final Set<String> seenPairs = ConcurrentHashMap.newKeySet();
    private final Set<String> seenApiGlobal = ConcurrentHashMap.newKeySet();

    // DOM XSS: cache nội dung đã scan + chống trùng issue
    private final Set<String> scannedContentHashes = ConcurrentHashMap.newKeySet();
    private final Set<String> seenIssues = ConcurrentHashMap.newKeySet();

    // Giới hạn để tránh lag: bỏ file quá lớn (thường là bundle/lib khổng lồ
    private static final int MAX_SCAN_BYTES = 3_000_000;   // ~3MB

    private static final boolean STRIP_TRAILING_SLASH = true;
    private final Map<String, Set<String>> paramsByPath = new ConcurrentHashMap<>();

    // ===== Pattern trích xuất API (giữ nguyên của bạn) =====
    private static final Pattern P_ABS = Pattern.compile("(https?://[A-Za-z0-9_\\-.:]+\\/[A-Za-z0-9_\\-./?&=%+=]+)");
    private static final Pattern P_ANY_QUOTED_PATH = Pattern.compile("(['\"])(/[A-Za-z0-9_\\-./?&=%+=]+)\\1", Pattern.CASE_INSENSITIVE);
    private static final Pattern P_HTML_ATTR_LEADING_SLASH = Pattern.compile("(href|src|action)\\s*=\\s*(['\"])(/[^'\" >]+)\\2", Pattern.CASE_INSENSITIVE);
    private static final Pattern P_QUOTE_PLUS = Pattern.compile("(['\"])(/[^'\"\\s>]+(?:=|/|\\?))\\1\\s*\\+", Pattern.CASE_INSENSITIVE);
    private static final Pattern P_URL_FIELD = Pattern.compile("\\burl\\s*:\\s*(['\"])\\s*(\\/?[A-Za-z0-9_\\-./?&=%+=]+)\\s*\\1", Pattern.CASE_INSENSITIVE);
    private static final Pattern P_AXIOS = Pattern.compile("\\baxios\\.(get|post|put|patch|delete|head|options)\\s*\\(\\s*(['\"])\\s*(\\/?[A-Za-z0-9_\\-./?&=%+=]+)\\s*\\2", Pattern.CASE_INSENSITIVE);
    private static final Pattern P_FETCH = Pattern.compile("\\bfetch\\s*\\(\\s*(['\"])\\s*(\\/?[A-Za-z0-9_\\-./?&=%+=]+)\\s*\\1", Pattern.CASE_INSENSITIVE);
    private static final Pattern P_HTML_DATA_URL = Pattern.compile("data-(url|href)\\s*=\\s*(['\"])(/[^'\" >]+)\\2", Pattern.CASE_INSENSITIVE);
    private static final Pattern P_HTML_ATTR_NO_QUOTE = Pattern.compile("(href|src|action)=(/[^\\s>]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern P_TEMPLATE_BACKTICK = Pattern.compile("`([^`]*(/[-A-Za-z0-9_\\-./?&=%+=]+)[^`]*)`");
    private static final Pattern P_TEMPLATE_COMPLEX = Pattern.compile("\\$\\{[^}]+}/([A-Za-z0-9_\\-./?&=%+=]+)");
    private static final Pattern P_TEMPLATE_AFTER_EXPR = Pattern.compile("\\$\\{[^}]+}\\s*/\\s*([A-Za-z0-9_\\-./?&=%+=]+)");
    private static final Pattern P_NO_SLASH_PREFIX = Pattern.compile("['\"]([A-Za-z0-9_\\-]+/[A-Za-z0-9_\\-./?&=%+=]+)['\"]");

    private static final Pattern P_MIME = Pattern.compile("(?i)^(application|text|image|audio|video)/.*");
    private static final Pattern P_NOISE_PREFIX = Pattern.compile("(?i)^(null|undefined|n/a)(/|$).*");
    private static final Pattern P_STATIC_EXT = Pattern.compile("(?i).+\\.(png|jpg|jpeg|gif|webp|bmp|ico|svg|xml|txt|map|css|scss|sass|less|js|mjs|cjs|ts|tsx|vue|otf|ttf|eot|woff2?|pdf|xhtml)(/.*)?$");
    private static final Pattern P_SOURCE_DIR = Pattern.compile("(?i)^/(src|node_modules|assets|static|vendor|lib)(/.*)?$");

    // ===== Nhận diện thư viện (chỉ để skip DOM XSS) =====
    private static final String[] LIB_NAME_HINTS = {"jquery", "angular", "react", "react-dom", "vue", "bootstrap", "lodash", "underscore", "moment", "d3", "three", "axios", "polyfill", "modernizr", "popper", "tailwind", "ember", "backbone", "knockout", "zepto", "prototype", "mootools", "swiper", "slick", "select2", "datatables", "chart", "gtm", "gtag", "analytics", "googletagmanager", "hotjar", "recaptcha", "stripe", "sentry", "fontawesome"};
    private static final Pattern VENDOR_DIR = Pattern.compile("(?i)/(node_modules|bower_components|vendor|vendors|libs?|dist|cdn|3rd-?party|third-?party)/");
    private static final Pattern LIB_BANNER = Pattern.compile("(?i)(/\\*!|/\\*\\*?)[^*]{0,80}(v?\\d+\\.\\d+\\.\\d+|copyright|\\(c\\)|license|MIT|Apache)");

    private static final ExecutorService executor = Executors.newFixedThreadPool(4);

    public MyHttpHandler(MontoyaApi api, APITab tab) {
        this.logging = api.logging();
        this.tab = tab;
        this.api = api;
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        HttpRequest req = responseReceived.initiatingRequest();
        String fullUrl = (req != null) ? req.url() : null;

        if (!isValidHttpUrl(fullUrl) || !safeIsInScope(fullUrl) || !isExtractableContentType(responseReceived)) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        executor.execute(() -> processResponse(responseReceived));
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    // ===== Trích API (giữ nguyên) =====
    private static void scan(String text, Pattern p, int groupIdx, Set<String> out) {
        Matcher m = p.matcher(text);
        while (m.find()) {
            String s = m.group(groupIdx);
            if (s != null && !s.isEmpty()) out.add(s);
        }
    }

    private static String stripQuery(String url) {
        return url.replaceAll("\\?.*$", "");
    }

    private Set<String> normalizeAndFilter(Set<String> raw) {
        LinkedHashSet<String> keep = new LinkedHashSet<>();
        for (String s : raw) {
            String cleaned = s;
            if (P_MIME.matcher(cleaned).matches() || P_NOISE_PREFIX.matcher(cleaned).matches()) continue;
            if (!cleaned.startsWith("http") && !cleaned.startsWith("/")) cleaned = "/" + cleaned;
            cleaned = cleaned.replaceAll("/{2,}", "/");
            String checkPath = stripQuery(cleaned);
            if (P_STATIC_EXT.matcher(checkPath).matches()) continue;
            if (P_SOURCE_DIR.matcher(checkPath).matches()) continue;
            if (cleaned.length() < 3 || cleaned.matches("^(/\\d+)+$")) continue;
            keep.add(cleaned);
        }
        return keep;
    }

    private Set<String> extractEndpointsFromText(String text) {
        LinkedHashSet<String> hits = new LinkedHashSet<>();
        scan(text, P_URL_FIELD, 2, hits);
        scan(text, P_ANY_QUOTED_PATH, 2, hits);
        scan(text, P_HTML_ATTR_LEADING_SLASH, 3, hits);
        scan(text, P_HTML_DATA_URL, 3, hits);
        scan(text, P_HTML_ATTR_NO_QUOTE, 2, hits);
        scan(text, P_QUOTE_PLUS, 2, hits);
        scan(text, P_TEMPLATE_COMPLEX, 1, hits);
        scan(text, P_NO_SLASH_PREFIX, 1, hits);
        scan(text, P_AXIOS, 3, hits);
        scan(text, P_FETCH, 2, hits);
        scan(text, P_ABS, 0, hits);
        scan(text, P_TEMPLATE_BACKTICK, 2, hits);
        scan(text, P_TEMPLATE_AFTER_EXPR, 1, hits);
        return normalizeAndFilter(hits);
    }

    private boolean isExtractableContentType(HttpResponseReceived r) {
        String ct = Optional.ofNullable(r.headerValue("Content-Type")).orElse("").toLowerCase(Locale.ROOT);
        if (ct.isEmpty()) return true;
        if (ct.contains("html")) return true;
        if (ct.contains("javascript") || ct.contains("ecmascript") || ct.contains("x-javascript")) return true;
        if (ct.startsWith("text/")) return true;
        if (ct.startsWith("image/") || ct.startsWith("video/") || ct.startsWith("audio/")) return false;
        if (ct.contains("octet-stream") || ct.contains("pdf") || ct.contains("font")) return false;
        return false;
    }

    private boolean safeIsInScope(String url) {
        try {
            return api.scope().isInScope(url);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private boolean isValidHttpUrl(String fullUrl) {
        try {
            if (fullUrl == null || fullUrl.isEmpty()) return false;
            return new URL(fullUrl).getProtocol().startsWith("http");
        } catch (Exception e) {
            return false;
        }
    }

    private String resolveToAbsolute(String pageUrl, String apiCandidate) {
        try {
            if (apiCandidate.startsWith("http://") || apiCandidate.startsWith("https://")) return apiCandidate;
            URL base = new URL(pageUrl);
            return stripQuery(new URL(base, apiCandidate).toString());
        } catch (Exception e) {
            return null;
        }
    }

    private static String hostPortOf(URL u) {
        String host = u.getHost();
        int port = u.getPort();
        if (port != -1 && port != u.getDefaultPort()) return host + ":" + port;
        return host;
    }

    private String apiGlobalKey(String absUrl) {
        try {
            URL u = new URL(absUrl);
            String path = u.getPath().replaceAll("/{2,}", "/");
            if (STRIP_TRAILING_SLASH && path.length() > 1 && path.endsWith("/"))
                path = path.substring(0, path.length() - 1);
            return (hostPortOf(u) + path).toLowerCase(Locale.ROOT);
        } catch (Exception e) {
            return absUrl.toLowerCase(Locale.ROOT);
        }
    }

    // ===== Nhận diện thư viện =====
    private boolean looksLikeLibrary(String url, String text) {
        String path;
        try {
            path = new URL(url).getPath().toLowerCase(Locale.ROOT);
        } catch (Exception e) {
            path = url.toLowerCase(Locale.ROOT);
        }

        if (VENDOR_DIR.matcher(path).find()) return true;

        String fileName = path.contains("/") ? path.substring(path.lastIndexOf('/') + 1) : path;
        for (String lib : LIB_NAME_HINTS) {
            if (fileName.contains(lib)) return true;
        }

        String head = text.length() > 500 ? text.substring(0, 500) : text;
        if (LIB_BANNER.matcher(head).find()) return true;

        return false;
    }

    private static String sha256(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] h = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : h) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return Integer.toString(s.hashCode());
        }
    }

    private void processResponse(HttpResponseReceived rr) {
        try {
            HttpRequest req = rr.initiatingRequest();
            if (req == null) return;

            String fullUrl = req.url();
            String body = rr.bodyToString();
            if (body == null || body.isEmpty()) return;

            // CHỐNG LAG 1: bỏ file quá lớn (parse regex rất nặng, hiếm khi đáng)
            if (body.length() > MAX_SCAN_BYTES) {
                logging.logToOutput("Bỏ qua file lớn (" + body.length() + " bytes): " + fullUrl);
                return;
            }

            String text = body.replace("\\/", "/");

            // CHỐNG LAG 2 + ĐÚNG YÊU CẦU: mỗi nội dung chỉ xử lý 1 lần (cả extract lẫn DOM XSS)
            String contentHash = sha256(text);
            if (!scannedContentHashes.add(contentHash)) {
                return;   // file/nội dung này đã xử lý rồi -> bỏ hẳn
            }

            // ---- Extract API (chạy cho mọi file, kể cả thư viện) ----
            Set<String> endpoints = extractEndpointsFromText(text);

            // CHỐNG LAG 3: gom thành 1 batch, đẩy sang UI 1 lần thay vì từng dòng
            List<Object[]> batch = new ArrayList<>();
            for (String apiPath : endpoints) {
                String absUrl = resolveToAbsolute(fullUrl, apiPath);
                if (absUrl == null || !safeIsInScope(absUrl)) continue;

                String globalKey = apiGlobalKey(absUrl);   // path đã chuẩn hoá, strip query

                // Gom param TRƯỚC khi dedup (param có thể nằm ở apiPath gốc)
                Set<String> ps = extractParams(apiPath);
                if (ps.isEmpty()) ps = extractParams(absUrl);
                if (!ps.isEmpty()) {
                    paramsByPath.computeIfAbsent(globalKey, k -> ConcurrentHashMap.newKeySet()).addAll(ps);
                }

                // Dedup hiển thị theo path (toàn phiên)
                if (!seenApiGlobal.add(globalKey)) continue;

                Set<String> collected = paramsByPath.getOrDefault(globalKey, Collections.emptySet());
                String display = collected.isEmpty() ? apiPath : apiPath + "  [params: " + String.join(", ", collected) + "]";

                batch.add(new Object[]{fullUrl, display});
            }

            // Đẩy cả batch sang APITab 1 lần (1 lần vẽ + 1 lần save thay vì N lần)
            if (!batch.isEmpty()) {
                tab.addEntriesBatch(batch);
            }

            // ---- DOM XSS: chỉ bỏ qua thư viện ----
            if (!looksLikeLibrary(fullUrl, text)) {
                for (DomXssScanner.Finding f : DomXssScanner.scan(text)) {
                    String issueKey = fullUrl + "|" + f.vulnType + "|" + f.sink + "|" + f.lineHint;
                    if (!seenIssues.add(issueKey)) continue;
                    reportIssue(rr, fullUrl, f);
                }
            }
        } catch (Throwable t) {
            logging.logToError("Extractor error: " + t.getMessage());
        }
    }

    private Set<String> extractParams(String urlOrPath) {
        Set<String> params = new LinkedHashSet<>();
        int q = urlOrPath.indexOf('?');
        if (q < 0 || q == urlOrPath.length() - 1) return params;
        String query = urlOrPath.substring(q + 1);
        for (String pair : query.split("&")) {
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            String name = (eq >= 0 ? pair.substring(0, eq) : pair).trim();
            if (!name.isEmpty() && !name.contains("${") && name.length() <= 64) {
                params.add(name);
            }
        }
        return params;
    }

    private void reportIssue(HttpResponseReceived rr, String url, DomXssScanner.Finding f) {
        try {
            AuditIssueSeverity sev = "HIGH".equals(f.severity) ? AuditIssueSeverity.HIGH : AuditIssueSeverity.MEDIUM;

            String detail = "<b>Possible " + escape(f.vulnType) + " (static heuristic)</b><br><br>" + "<b>Source:</b> " + escape(f.source == null ? "-" : f.source) + "<br>" + "<b>Sink:</b> " + escape(f.sink) + "<br>" + "<b>Line (approx):</b> " + f.lineHint + "<br><br>" + "<b>Snippet:</b><br><pre>" + escape(f.snippet) + "</pre><br>" + "Phát hiện bằng regex tĩnh (source và sink nằm gần nhau). " + "Cần xác nhận thủ công xem dữ liệu có thực sự chảy từ source vào sink hay không.";

            String remediation = remediationFor(f.vulnType);

            HttpRequestResponse evidence = HttpRequestResponse.httpRequestResponse(rr.initiatingRequest(), rr);
            List<Marker> markers = buildMarkers(rr, f);
            if (!markers.isEmpty()) evidence = evidence.withResponseMarkers(markers);

            AuditIssue issue = AuditIssue.auditIssue(f.vulnType + " (heuristic): " + f.sink, detail, remediation, url, sev, AuditIssueConfidence.TENTATIVE, null, null, sev, evidence);
            api.siteMap().add(issue);
        } catch (Throwable t) {
            logging.logToError("Lỗi report issue: " + t.getMessage());
        }
    }

    private String remediationFor(String vulnType) {
        switch (vulnType) {
            case "DOM XSS":
                return "Tránh đưa dữ liệu attacker kiểm soát vào sink thực thi/render. " + "Dùng textContent thay innerHTML, hoặc sanitize bằng DOMPurify.";
            case "DOM Open Redirect":
                return "Không dùng dữ liệu từ source để điều hướng. Nếu cần, validate URL " + "theo allowlist domain/path, từ chối URL tuyệt đối tới domain ngoài.";
            case "DOM Request Manipulation":
                return "Không xây dựng URL request từ dữ liệu attacker kiểm soát. " + "Validate/allowlist endpoint, tránh để source quyết định host đích.";
            case "DOM Cookie Manipulation":
                return "Không ghi cookie từ dữ liệu attacker kiểm soát mà chưa validate. " + "Tránh để source ảnh hưởng tên/giá trị cookie.";
            default:
                return "Validate và sanitize dữ liệu từ source trước khi đưa vào sink.";
        }
    }

    /**
     * Tìm vị trí sink trong response GỐC để bôi vàng.
     * Dùng indexOf trên response thật, tránh lệch offset do unescape "\/".
     */
    private List<Marker> buildMarkers(HttpResponseReceived rr, DomXssScanner.Finding f) {
        List<Marker> markers = new ArrayList<>();
        try {
            String fullResponse = rr.toString();   // toàn bộ response (header + body)
            // Tìm sink. Vì sink có thể xuất hiện nhiều lần, ưu tiên gần vị trí body.
            int idx = fullResponse.indexOf(f.sink);
            if (idx >= 0) {
                // Bôi vàng cả cụm nhỏ quanh sink cho dễ thấy (sink + chút ngữ cảnh)
                int start = idx;
                int end = Math.min(fullResponse.length(), idx + f.sink.length());
                markers.add(Marker.marker(Range.range(start, end)));
            }
        } catch (Throwable t) {
            logging.logToError("Marker error: " + t.getMessage());
        }
        return markers;
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    public void clearCache() {
        seenPairs.clear();
        seenApiGlobal.clear();
        scannedContentHashes.clear();
        seenIssues.clear();
        paramsByPath.clear();
    }
}