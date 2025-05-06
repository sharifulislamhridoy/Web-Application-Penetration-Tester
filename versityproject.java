
package zaberp.zab;

import java.io.*;
import java.net.*;
import java.security.cert.X509Certificate;
import java.sql.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.Date;
import java.util.List;
import java.util.concurrent.*;
import java.util.stream.Collectors;
import javax.net.ssl.*;
import javax.servlet.*;
import javax.servlet.http.*;
import javax.servlet.annotation.*;

import com.itextpdf.text.*;
import com.itextpdf.text.pdf.*;
import com.itextpdf.text.Font.FontFamily;

//@WebServlet("/pentest")
public class versityproject extends HttpServlet {
    
    private static ConcurrentMap<String, ScanSession> scanHistory = new ConcurrentHashMap<>();
    private static ExecutorService scanExecutor = Executors.newFixedThreadPool(5);
    private static boolean disableSSLVerification = true; // Configurable flag
    
    private static final String[] XSS_PAYLOADS = {
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "\"><script>alert(1)</script>",
        "javascript:alert(1)",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src=\"javascript:alert(1)\">"
    };
    
    private static final String[] SQLI_PAYLOADS = {
        "' OR '1'='1",
        "' OR 1=1--",
        "\" OR \"\"=\"",
        "admin'--",
        "') OR ('1'='1--",
        "\" OR 1=1--",
        "' UNION SELECT null,username,password FROM users--"
    };
    
    private static final String[] DIRECTORIES = {
        "admin", "login", "wp-admin", "backup", "config", 
        "phpmyadmin", "test", "secret", "uploads", "cgi-bin",
        "includes", "sql", "db", "database", "backups"
    };
    
    private static final String[] FILE_EXTENSIONS = {
        ".bak", ".old", ".zip", ".tar", ".gz", 
        ".sql", ".txt", ".rar", ".7z", ".conf"
    };
    
    // SSL Configuration
    private static void configureSSL() {
        try {
            // Create a trust manager that does not validate certificate chains
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                    }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    }
                }
            };

            // Install the all-trusting trust manager
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            // Create all-trusting host name verifier
            HostnameVerifier allHostsValid = (hostname, session) -> true;
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        if ("all".equals(request.getParameter("clear"))) {
            scanHistory.clear();
            response.sendRedirect(request.getContextPath() + request.getServletPath());
            return;
        }
        
        // Check for SSL verification parameter
        String sslVerifyParam = request.getParameter("sslVerify");
        if (sslVerifyParam != null) {
            disableSSLVerification = !"true".equals(sslVerifyParam);
        }
        
        String downloadParam = request.getParameter("download");
        String urlParam = request.getParameter("url");
        
        if (downloadParam != null && urlParam != null) {
            handleDownloadRequest(request, response, urlParam, downloadParam);
            return;
        }
        
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        
        out.println(getHtmlHeader());
        out.println(getScanForm());
        
        if (urlParam != null && scanHistory.containsKey(urlParam)) {
            displayScanResults(out, urlParam, scanHistory.get(urlParam));
        }
        
        out.println(getHistorySection());
        out.println(getHtmlFooter());
    }
    
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String targetUrl = request.getParameter("url");
        String scanType = request.getParameter("scanType");
        String sslVerify = request.getParameter("sslVerify");
        
        // Update SSL verification setting
        disableSSLVerification = !"on".equals(sslVerify);
        
        if (targetUrl != null && !targetUrl.isEmpty()) {
            targetUrl = normalizeUrl(targetUrl);
            clearScanResults(targetUrl);
            
            ScanSession session = new ScanSession(targetUrl);
            scanHistory.put(targetUrl, session);
            
            final String finalTargetUrl = targetUrl;
            final String finalScanType = scanType;
            scanExecutor.submit(() -> performScan(finalTargetUrl, finalScanType, session));
            
            response.sendRedirect(request.getContextPath() + request.getServletPath() + "?url=" + encodeURL(targetUrl));
            return;
        }
        
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        out.println(getHtmlHeader());
        out.println(getScanForm());
        out.println(getHistorySection());
        out.println(getHtmlFooter());
    }
    
    private void clearScanResults(String targetUrl) {
        scanHistory.remove(targetUrl);
    }
    
    private void handleDownloadRequest(HttpServletRequest request, HttpServletResponse response, 
                                      String targetUrl, String format) throws IOException {
        ScanSession session = scanHistory.get(targetUrl);
        if (session == null) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "Scan results not found");
            return;
        }

        if ("text".equalsIgnoreCase(format)) {
            String content = generateTextReport(session);
            String filename = "scan-report-" + targetUrl.replaceAll("[^a-zA-Z0-9.-]", "-") + ".txt";
            response.setContentType("text/plain");
            response.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");
            
            try (PrintWriter writer = response.getWriter()) {
                writer.write(content);
            }
        } else if ("pdf".equalsIgnoreCase(format)) {
            generatePdfReport(response, session);
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Unsupported format");
        }
    }
    
    private String generateTextReport(ScanSession session) {
        StringBuilder report = new StringBuilder();
        report.append("Web Application Penetration Test Report\n");
        report.append("=======================================\n\n");
        report.append("Target URL: ").append(session.getTargetUrl()).append("\n");
        report.append("Scan Status: ").append(session.getStatus()).append("\n");
        report.append("Start Time: ").append(formatDate(session.getStartTime())).append("\n");
        if (session.getEndTime() != null) {
            report.append("End Time: ").append(formatDate(session.getEndTime())).append("\n");
        }
        report.append("\n");
        
        report.append("Vulnerabilities Found: ").append(session.getResults().size()).append("\n\n");
        
        Map<String, List<ScanResult>> groupedResults = new HashMap<>();
        for (ScanResult result : session.getResults()) {
            groupedResults.computeIfAbsent(result.getType(), k -> new ArrayList<>()).add(result);
        }
        
        for (Map.Entry<String, List<ScanResult>> entry : groupedResults.entrySet()) {
            report.append(entry.getKey()).append(" (").append(entry.getValue().size()).append(")\n");
            report.append(String.join("", Collections.nCopies(entry.getKey().length() + 3 + String.valueOf(entry.getValue().size()).length() + 2, "-"))).append("\n");
            
            for (ScanResult result : entry.getValue()) {
                report.append("- ").append(result.getVulnerability()).append("\n");
                report.append("  Payload: ").append(result.getPayload()).append("\n");
                report.append("  Risk Level: ").append(getRiskLevel(result.getType())).append("\n");
                report.append("  Attack Type: ").append(getAttackDescription(result.getType())).append("\n");
                report.append("  Suggestion: ").append(getSuggestion(result.getType())).append("\n\n");
            }
        }
        
        report.append("\n=== Report End ===");
        return report.toString();
    }
    
    private void generatePdfReport(HttpServletResponse response, ScanSession session) throws IOException {
        response.setContentType("application/pdf");
        String filename = "scan-report-" + session.getTargetUrl().replaceAll("[^a-zA-Z0-9.-]", "-") + ".pdf";
        response.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");

        try {
            Document document = new Document(PageSize.A4.rotate());
            PdfWriter writer = PdfWriter.getInstance(document, response.getOutputStream());
            document.open();

            HeaderFooter event = new HeaderFooter();
            writer.setPageEvent(event);

            Font titleFont = new Font(FontFamily.HELVETICA, 20, Font.BOLD, BaseColor.DARK_GRAY);
            Paragraph title = new Paragraph("Penetration Test Report", titleFont);
            title.setAlignment(Element.ALIGN_CENTER);
            title.setSpacingAfter(25);
            document.add(title);

            PdfPTable metaTable = new PdfPTable(2);
            metaTable.setWidthPercentage(100);
            metaTable.setSpacingBefore(15f);
            metaTable.setSpacingAfter(15f);
            metaTable.setWidths(new float[]{1f, 3f});

            addMetaRow(metaTable, "Target URL:", session.getTargetUrl());
            addMetaRow(metaTable, "Scan Status:", session.getStatus());
            addMetaRow(metaTable, "Start Time:", formatDate(session.getStartTime()));
            addMetaRow(metaTable, "End Time:", 
                session.getEndTime() != null ? formatDate(session.getEndTime()) : "N/A");
            addMetaRow(metaTable, "Total Vulnerabilities:", 
                String.valueOf(session.getResults().size()));

            document.add(metaTable);

            PdfPTable dataTable = new PdfPTable(6);
            dataTable.setWidthPercentage(100);
            dataTable.setSpacingBefore(15f);
            dataTable.setWidths(new float[]{1f, 2f, 2f, 1f, 3f, 3f});

            String[] headers = {"Type", "Vulnerability", "Payload", "Risk", "Attack Pattern", "Recommendations"};
            for (String header : headers) {
                PdfPCell cell = new PdfPCell(new Phrase(header, getHeaderFont()));
                cell.setBackgroundColor(new BaseColor(63, 81, 181));
                cell.setPadding(8);
                cell.setBorderColor(BaseColor.WHITE);
                cell.setHorizontalAlignment(Element.ALIGN_CENTER);
                dataTable.addCell(cell);
            }

            Font contentFont = new Font(FontFamily.HELVETICA, 10);
            for (ScanResult result : session.getResults()) {
                addDataRow(dataTable, result.getType(), contentFont, BaseColor.WHITE);
                addDataRow(dataTable, result.getVulnerability(), contentFont, new BaseColor(245, 245, 245));
                addDataRow(dataTable, result.getPayload(), contentFont, BaseColor.WHITE);
                addDataRow(dataTable, getRiskLevel(result.getType()), contentFont, getRiskColor(result.getType()));
                addDataRow(dataTable, getAttackDescription(result.getType()), contentFont, BaseColor.WHITE);
                addDataRow(dataTable, getSuggestion(result.getType()), contentFont, new BaseColor(245, 245, 245));
            }

            document.add(dataTable);
            document.close();
        } catch (DocumentException e) {
            throw new IOException("Error generating PDF: " + e.getMessage(), e);
        }
    }

    private Font getHeaderFont() {
        return new Font(FontFamily.HELVETICA, 12, Font.BOLD, BaseColor.WHITE);
    }

    private BaseColor getRiskColor(String type) {
        switch (type) {
            case "XSS":
            case "SQLi": return new BaseColor(244, 67, 54);
            case "Directory":
            case "File": return new BaseColor(255, 193, 7);
            case "Headers": return new BaseColor(76, 175, 80);
            default: return BaseColor.LIGHT_GRAY;
        }
    }

    private void addMetaRow(PdfPTable table, String label, String value) {
        Font labelFont = new Font(FontFamily.HELVETICA, 10, Font.BOLD);
        Font valueFont = new Font(FontFamily.HELVETICA, 10);
        
        PdfPCell labelCell = new PdfPCell(new Phrase(label, labelFont));
        labelCell.setBorder(PdfPCell.NO_BORDER);
        labelCell.setPadding(5);
        table.addCell(labelCell);

        PdfPCell valueCell = new PdfPCell(new Phrase(value, valueFont));
        valueCell.setBorder(PdfPCell.NO_BORDER);
        valueCell.setPadding(5);
        table.addCell(valueCell);
    }

    private void addDataRow(PdfPTable table, String text, Font font, BaseColor bgColor) {
        PdfPCell cell = new PdfPCell(new Phrase(text, font));
        cell.setBackgroundColor(bgColor);
        cell.setPadding(8);
        cell.setBorderColor(BaseColor.LIGHT_GRAY);
        cell.setBorderWidth(0.5f);
        table.addCell(cell);
    }

    private static class HeaderFooter extends PdfPageEventHelper {
        public void onEndPage(PdfWriter writer, Document document) {
            PdfPTable footer = new PdfPTable(1);
            footer.setTotalWidth(document.getPageSize().getWidth() - 80);
            
            Font font = new Font(FontFamily.HELVETICA, 8, Font.ITALIC, BaseColor.DARK_GRAY);
            
            PdfPCell cell1 = new PdfPCell(new Phrase("Confidential Report - Generated by Web Penetration Tester", font));
            cell1.setBorder(PdfPCell.NO_BORDER);
            cell1.setHorizontalAlignment(Element.ALIGN_CENTER);
            footer.addCell(cell1);
            
            PdfPCell cell2 = new PdfPCell(new Phrase("Developed By: Safayet | Shariful", font));
            cell2.setBorder(PdfPCell.NO_BORDER);
            cell2.setHorizontalAlignment(Element.ALIGN_CENTER);
            footer.addCell(cell2);
            
            footer.writeSelectedRows(0, -1, 40, 30, writer.getDirectContent());
        }
    }
    
    private String formatDate(Date date) {
        if (date == null) return "N/A";
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        return sdf.format(date);
    }
    
    private void performScan(String targetUrl, String scanType, ScanSession session) {
        try {
            session.setStatus("Scanning in progress...");
            
            if (scanType == null || scanType.equals("full")) {
                session.addResults(testForXSS(targetUrl));
                session.addResults(testForSQLi(targetUrl));
                session.addResults(testDirectories(targetUrl));
                session.addResults(testCommonFiles(targetUrl));
                session.addResults(testHeaders(targetUrl));
            } else if (scanType.equals("xss")) {
                session.addResults(testForXSS(targetUrl));
            } else if (scanType.equals("sqli")) {
                session.addResults(testForSQLi(targetUrl));
            } else if (scanType.equals("dir")) {
                session.addResults(testDirectories(targetUrl));
                session.addResults(testCommonFiles(targetUrl));
            } else if (scanType.equals("headers")) {
                session.addResults(testHeaders(targetUrl));
            }
            
            session.setStatus("Scan completed");
            session.setCompleted(true);
        } catch (Exception e) {
            session.setStatus("Scan failed: " + e.getMessage());
            session.addResult(new ScanResult("Error", "Scan Error", e.toString()));
        }
    }
    
    private List<ScanResult> testForXSS(String targetUrl) {
        List<ScanResult> results = new ArrayList<>();
        boolean sslErrorOccurred = false;
        
        for (String payload : XSS_PAYLOADS) {
            try {
                if (sslErrorOccurred) break;
                
                String testUrl = targetUrl + (targetUrl.contains("?") ? "&" : "?") + "test=" + encodeURL(payload);
                String response = sendGetRequest(testUrl);
                
                if (response.contains(payload) || response.toLowerCase().contains("alert(1)")) {
                    results.add(new ScanResult("XSS", "Reflected XSS found", payload));
                }
            } catch (IOException e) {
                if (e.getMessage().contains("SSL Handshake Failed")) {
                    results.add(new ScanResult("SSL", "SSL Certificate Error", 
                        "Could not verify SSL certificate for XSS testing"));
                    sslErrorOccurred = true;
                } else {
                    results.add(new ScanResult("Error", "XSS Test Failed", e.getMessage()));
                }
            }
        }
        return results;
    }
    
    private List<ScanResult> testForSQLi(String targetUrl) {
        List<ScanResult> results = new ArrayList<>();
        boolean sslErrorOccurred = false;
        
        for (String payload : SQLI_PAYLOADS) {
            try {
                if (sslErrorOccurred) break;
                
                String testUrl = targetUrl + (targetUrl.contains("?") ? "&" : "?") + "id=" + encodeURL(payload);
                String response = sendGetRequest(testUrl);
                
                if (isSqlError(response)) {
                    results.add(new ScanResult("SQLi", "Possible SQL Injection", payload));
                }
            } catch (IOException e) {
                if (e.getMessage().contains("SSL Handshake Failed")) {
                    results.add(new ScanResult("SSL", "SSL Certificate Error", 
                        "Could not verify SSL certificate for SQLi testing"));
                    sslErrorOccurred = true;
                } else {
                    results.add(new ScanResult("Error", "SQLi Test Failed", e.getMessage()));
                }
            }
        }
        return results;
    }
    
    private boolean isSqlError(String response) {
        String lowerResponse = response.toLowerCase();
        return lowerResponse.contains("error in your sql syntax") || 
               lowerResponse.contains("warning: mysql") ||
               lowerResponse.contains("unclosed quotation mark") ||
               lowerResponse.contains("sql exception") ||
               lowerResponse.contains("sql error") ||
               lowerResponse.contains("database error");
    }
    
    private List<ScanResult> testDirectories(String targetUrl) {
        List<ScanResult> results = new ArrayList<>();
        boolean sslErrorOccurred = false;
        
        for (String dir : DIRECTORIES) {
            try {
                if (sslErrorOccurred) break;
                
                String testUrl = targetUrl.endsWith("/") ? 
                    targetUrl + dir : targetUrl + "/" + dir;
                
                int responseCode = getResponseCode(testUrl);
                
                if (responseCode == 200) {
                    results.add(new ScanResult("Directory", "Accessible directory found", dir));
                } else if (responseCode == 403) {
                    results.add(new ScanResult("Directory", "Directory exists but access forbidden", dir));
                } else if (responseCode == 401) {
                    results.add(new ScanResult("Directory", "Directory requires authentication", dir));
                }
            } catch (IOException e) {
                if (e.getMessage().contains("SSL Handshake Failed")) {
                    results.add(new ScanResult("SSL", "SSL Certificate Error", 
                        "Could not verify SSL certificate for directory testing"));
                    sslErrorOccurred = true;
                } else {
                    results.add(new ScanResult("Error", "Directory Test Failed", e.getMessage()));
                }
            }
        }
        
        return results;
    }
    
    private List<ScanResult> testCommonFiles(String targetUrl) {
        List<ScanResult> results = new ArrayList<>();
        String baseUrl = targetUrl.endsWith("/") ? targetUrl : targetUrl + "/";
        boolean sslErrorOccurred = false;
        
        String[] commonFiles = {
            "config.php", "settings.php", "wp-config.php", 
            "web.config", ".htaccess", "robots.txt"
        };
        
        for (String file : commonFiles) {
            try {
                if (sslErrorOccurred) break;
                
                String testUrl = baseUrl + file;
                int responseCode = getResponseCode(testUrl);
                
                if (responseCode == 200) {
                    results.add(new ScanResult("File", "Sensitive file accessible", file));
                }
            } catch (IOException e) {
                if (e.getMessage().contains("SSL Handshake Failed")) {
                    results.add(new ScanResult("SSL", "SSL Certificate Error", 
                        "Could not verify SSL certificate for file testing"));
                    sslErrorOccurred = true;
                } else {
                    results.add(new ScanResult("Error", "File Test Failed", e.getMessage()));
                }
            }
        }
        
        for (String ext : FILE_EXTENSIONS) {
            try {
                if (sslErrorOccurred) break;
                
                String testUrl = baseUrl + "index" + ext;
                int responseCode = getResponseCode(testUrl);
                
                if (responseCode == 200) {
                    results.add(new ScanResult("File", "Backup file found", "index" + ext));
                }
            } catch (IOException e) {
                if (e.getMessage().contains("SSL Handshake Failed")) {
                    results.add(new ScanResult("SSL", "SSL Certificate Error", 
                        "Could not verify SSL certificate for file testing"));
                    sslErrorOccurred = true;
                } else {
                    results.add(new ScanResult("Error", "File Test Failed", e.getMessage()));
                }
            }
        }
        
        return results;
    }
    
    private List<ScanResult> testHeaders(String targetUrl) {
        List<ScanResult> results = new ArrayList<>();
        
        try {
            URL url = new URL(targetUrl);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            
            Map<String, List<String>> headers = con.getHeaderFields();
            
            if (!headers.containsKey("X-XSS-Protection")) {
                results.add(new ScanResult("Headers", "Missing X-XSS-Protection header", "Recommended: X-XSS-Protection: 1; mode=block"));
            }
            
            if (!headers.containsKey("X-Content-Type-Options")) {
                results.add(new ScanResult("Headers", "Missing X-Content-Type-Options header", "Recommended: X-Content-Type-Options: nosniff"));
            }
            
            if (!headers.containsKey("X-Frame-Options")) {
                results.add(new ScanResult("Headers", "Missing X-Frame-Options header", "Recommended: X-Frame-Options: DENY"));
            }
            
            if (!headers.containsKey("Content-Security-Policy")) {
                results.add(new ScanResult("Headers", "Missing Content-Security-Policy header", "Recommended CSP header can help prevent XSS"));
            }
            
            if (headers.containsKey("Server")) {
                String server = headers.get("Server").get(0);
                results.add(new ScanResult("Headers", "Server information disclosed", "Server: " + server));
            }
            
        } catch (Exception e) {
            results.add(new ScanResult("Error", "Header Test Failed", e.getMessage()));
        }
        
        return results;
    }
    
    private int getResponseCode(String url) throws IOException {
        HttpURLConnection con = null;
        try {
            if (url.startsWith("https://") && disableSSLVerification) {
                configureSSL();
            }
            
            URL obj = new URL(url);
            con = (HttpURLConnection) obj.openConnection();
            con.setRequestMethod("GET");
            con.setConnectTimeout(5000);
            con.setReadTimeout(5000);
            return con.getResponseCode();
        } catch (SSLHandshakeException e) {
            throw new IOException("SSL Handshake Failed: " + e.getMessage());
        } finally {
            if (con != null) con.disconnect();
        }
    }
    
    private String sendGetRequest(String url) throws IOException {
        HttpURLConnection con = null;
        try {
            if (url.startsWith("https://") && disableSSLVerification) {
                configureSSL();
            }
            
            URL obj = new URL(url);
            con = (HttpURLConnection) obj.openConnection();
            con.setRequestMethod("GET");
            con.setConnectTimeout(5000);
            con.setReadTimeout(5000);
            
            try (BufferedReader in = new BufferedReader(
                new InputStreamReader(con.getInputStream()))) {
                return in.lines().collect(Collectors.joining());
            }
        } catch (SSLHandshakeException e) {
            throw new IOException("SSL Handshake Failed: " + e.getMessage());
        } finally {
            if (con != null) con.disconnect();
        }
    }
    
    private String getSuggestion(String type) {
        switch (type) {
            case "XSS":
                return "Implement input sanitization and output encoding. Use Content Security Policy (CSP).";
            case "SQLi":
                return "Use prepared statements and parameterized queries. Implement proper input validation.";
            case "Directory":
                return "Remove unnecessary directories or implement access controls. Use proper directory permissions.";
            case "File":
                return "Remove sensitive files from production. Implement proper file access controls.";
            case "Headers":
                return "Add missing security headers. Implement HSTS and CSP headers.";
            case "Error":
                return "Review error handling mechanisms. Implement custom error pages.";
            default:
                return "Review application security controls. Conduct further investigation.";
        }
    }
    
    private String getAttackDescription(String type) {
        switch (type) {
            case "XSS":
                return "Client-side code injection through untrusted inputs";
            case "SQLi":
                return "Database query manipulation via malicious SQL payloads";
            case "Directory":
                return "Unauthorized directory structure enumeration";
            case "File":
                return "Sensitive file exposure through predictable paths";
            case "Headers":
                return "Security misconfiguration through missing HTTP headers";
            case "Error":
                return "Information leakage via detailed error messages";
            default:
                return "General security vulnerability requiring investigation";
        }
    }
    
    private void displayScanResults(PrintWriter out, String targetUrl, ScanSession session) {
        out.println("<div class='results-container'>");
        out.println("<h2>Scan Results for: " + escapeHtml(targetUrl) + "</h2>");
        out.println("<p>Status: " + session.getStatus() + "</p>");
        
        if (session.isCompleted()) {
            out.println("<div class='summary'>");
            out.println("<h3>Scan Summary</h3>");
            out.println("<p>Total vulnerabilities found: " + session.getResults().size() + "</p>");
            
            Map<String, Integer> counts = new HashMap<>();
            for (ScanResult result : session.getResults()) {
                counts.merge(result.getType(), 1, Integer::sum);
            }
            
            out.println("<ul>");
            for (Map.Entry<String, Integer> entry : counts.entrySet()) {
                out.println("<li>" + entry.getKey() + ": " + entry.getValue() + "</li>");
            }
            out.println("</ul>");
            out.println("</div>");
            
            out.println("<div class='results'>");
            out.println("<table>");
            out.println("<tr><th>Type</th><th>Vulnerability</th><th>Payload</th><th>Risk</th><th>Attack Description</th><th>Suggestions</th></tr>");
            
            for (ScanResult result : session.getResults()) {
                out.println("<tr class='" + result.getType().toLowerCase() + "'>");
                out.println("<td>" + result.getType() + "</td>");
                out.println("<td>" + result.getVulnerability() + "</td>");
                out.println("<td>" + escapeHtml(result.getPayload()) + "</td>");
                out.println("<td>" + getRiskLevel(result.getType()) + "</td>");
                out.println("<td>" + getAttackDescription(result.getType()) + "</td>");
                out.println("<td>" + getSuggestion(result.getType()) + "</td>");
                out.println("</tr>");
            }
            
            out.println("</table>");
            out.println("</div>");
            
            out.println("<div class='export-options'>");
            out.println("<h3>Export Report</h3>");
            out.println("<a href='?url=" + encodeURL(targetUrl) + "&download=text'>Download as Text File</a> | ");
            out.println("<a href='?url=" + encodeURL(targetUrl) + "&download=pdf'>Download as PDF</a>");
            out.println("</div>");
        } else {
            out.println("<div id='progress' style='"
                    + "background: #e7f3fe;"
                    + "padding: 15px;"
                    + "border-radius: 5px;"
                    + "margin: 20px 0;"
                    + "'>");
            out.println("<p>Scan is in progress. This page will refresh automatically...</p>");
            
            out.println("<div style='"
                    + "width: 100%;"
                    + "height: 20px;"
                    + "background-color: #f5f5f5;"
                    + "border-radius: 10px;"
                    + "overflow: hidden;"
                    + "box-shadow: inset 0 1px 2px rgba(0,0,0,0.1);"
                    + "'>");
            out.println("<div style='"
                    + "height: 100%;"
                    + "background: linear-gradient(90deg, #4CAF50, #8BC34A);"
                    + "border-radius: 10px;"
                    + "animation: progress 2s ease infinite, colorChange 3s ease infinite;"
                    + "background-size: 200% 100%;"
                    + "width: 50%;"
                    + "'>");
            out.println("</div>");
            out.println("</div>");
            
            out.println("<style>"
                    + "@keyframes progress {"
                    + "  0% { width: 30%; }"
                    + "  50% { width: 70%; }"
                    + "  100% { width: 30%; }"
                    + "}"
                    + "@keyframes colorChange {"
                    + "  0% { background-position: 0% 50%; }"
                    + "  50% { background-position: 100% 50%; }"
                    + "  100% { background-position: 0% 50%; }"
                    + "}"
                    + "</style>");
            
            out.println("</div>");
            
            out.println("<script>");
            out.println("setTimeout(function() { location.reload(); }, 5000);");
            out.println("</script>");
        }
        
        out.println("</div>");
    }
    
    private String getRiskLevel(String type) {
        switch (type) {
            case "XSS":
            case "SQLi":
                return "High";
            case "Directory":
            case "File":
                return "Medium";
            case "Headers":
                return "Low";
            default:
                return "Info";
        }
    }
    private String getHtmlHeader() {
        return "<!DOCTYPE html>\n" +
               "<html>\n" +
               "<head>\n" +
               "<title>Web Application Penetration Tester</title>\n" +
               "<meta charset='UTF-8'>\n" +
               "<meta name='viewport' content='width=device-width, initial-scale=1.0'>\n" +
               "<style>\n" +
               "  body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }\n" +
               "  .container { max-width: 1400px; margin: 0 auto; }\n" +
               "  td:nth-child(5) { width: 25%; }\n" + // Attack Description
               "  td:nth-child(6) { width: 25%; }\n" + // Suggestions
               "  .header-banner { background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }\n" +
               "  .header-banner h1 { margin: 0; font-size: 2.2em; text-shadow: 1px 1px 3px rgba(0,0,0,0.3); }\n" +
               "  .credits { margin-top: 10px; font-size: 0.9em; opacity: 0.9; }\n" +
               "  .credits p { margin: 5px 0; }\n" +
               "  form { background: #f5f5f5; padding: 20px; border-radius: 5px; margin-bottom: 20px; }\n" +
               "  input[type=text] { width: 100%; max-width: 500px; padding: 10px; margin: 5px 0; }\n" +
               "  select { padding: 10px; margin: 5px 0; }\n" +
               "  input[type=submit] { padding: 10px 20px; background: #4CAF50; color: white; border: none; border-radius: 4px; cursor: pointer; }\n" +
               "  input[type=button] { padding: 10px 20px; color: white; border: none; border-radius: 4px; cursor: pointer; }\n" +
               "  input[type=submit]:hover { background: #45a049; }\n" +
               "  table { width: 100%; border-collapse: collapse; margin: 20px 0; }\n" +
               "  th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }\n" +
               "  th { background-color: #f2f2f2; position: sticky; top: 0; }\n" +
               "  tr:nth-child(even) { background-color: #f9f9f9; }\n" +
               "  tr:hover { background-color: #f1f1f1; }\n" +
               "  .xss { background-color: #ffdddd; }\n" +
               "  .sqli { background-color: #ffcccc; }\n" +
               "  .directory { background-color: #fff3cd; }\n" +
               "  .file { background-color: #ffeeba; }\n" +
               "  .headers { background-color: #d4edda; }\n" +
               "  .error { background-color: #f8d7da; }\n" +
               "  .history { margin-top: 30px; }\n" +
               "  .results-container { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }\n" +
               "  .summary { background: #e7f3fe; padding: 15px; border-left: 6px solid #2196F3; margin-bottom: 20px; }\n" +
               "  .progress { background: #e7f3fe; padding: 15px; border-radius: 5px; margin: 20px 0; }\n" +
               "  .progress-bar { width: 100%; background-color: #ddd; border-radius: 4px; }\n" +
               "  .progress-value { width: 50%; height: 20px; background-color: #4CAF50; border-radius: 4px; animation: progress 2s infinite; }\n" +
               "  @keyframes progress { 0% { width: 30%; } 50% { width: 70%; } 100% { width: 30%; } }\n" +
               "  .export-options { margin: 20px 0; }\n" +
               "  .export-options a { padding: 8px 16px; background: #4CAF50; color: white; text-decoration: none; border-radius: 4px; margin-right: 10px; }\n" +
               "  .export-options a:hover { background: #45a049; }\n" +
               "  @media (max-width: 600px) { .container { padding: 10px; } th, td { padding: 8px; } .header-banner h1 { font-size: 1.8em; } }\n" +
               "</style>\n" +
               "</head>\n" +
               "<body>\n" +
               "<div class='container'>\n" +
               "<div class='header-banner'>\n" +
               "<h1>Web Application Penetration Tester</h1>\n" +
               "<div class='credits'>\n" +
               "<p>Developed By Shariful Islam (ID: 24110) | Safayet Ullah (ID: 24118)</p>\n" +
               "</div>\n" +
               "</div>\n";
    }
    
    private String getScanForm() {
        return "<form method='POST'>\n" +
               "<h2>Scan a Website</h2>\n" +
               "<p>URL: <input type='text' name='url' placeholder='https://example.com' required></p>\n" +
               "<p>Scan Type: \n" +
               "<select name='scanType'>\n" +
               "<option value='full'>Full Scan (XSS, SQLi, Directories, Files, Headers)</option>\n" +
               "<option value='xss'>XSS Only</option>\n" +
               "<option value='sqli'>SQL Injection Only</option>\n" +
               "<option value='dir'>Directory and File Search</option>\n" +
               "<option value='headers'>Security Headers Check</option>\n" +
               "</select></p>\n" +
               "<p><input type='submit' value='Start Scan'>\n" +
               "<input type='button' value='Clear Results' onclick='clearResults()' style='margin-left: 10px; background: #f44336;'></p>\n" +
               "</form>\n" +
               "<script>\n" +
               "function clearResults() {\n" +
               "  if(confirm('Are you sure you want to clear all scan results?')) {\n" +
               "    window.location.href = '?clear=all';\n" +
               "  }\n" +
               "}\n" +
               "</script>\n";
    }
    
    
    
    private String getHistorySection() {
        if (scanHistory.isEmpty()) {
            return "";
        }
        
        StringBuilder sb = new StringBuilder();
        sb.append("<div class='history'>\n");
        sb.append("<h2>Scan History</h2>\n");
        sb.append("<table>\n");
        sb.append("<tr><th>URL</th><th>Findings</th><th>Status</th><th>Actions</th></tr>\n");
        
        for (Map.Entry<String, ScanSession> entry : scanHistory.entrySet()) {
            String url = entry.getKey();
            ScanSession session = entry.getValue();
            
            sb.append("<tr>");
            sb.append("<td><a href='?url=").append(encodeURL(url)).append("'>").append(url).append("</a></td>");
            sb.append("<td>").append(session.getResults().size()).append("</td>");
            sb.append("<td>").append(session.getStatus()).append("</td>");
            sb.append("<td><a href='?url=").append(encodeURL(url)).append("'>View</a> | ");
            sb.append("<a href='?url=").append(encodeURL(url)).append("&download=text'>Text</a> | ");
            sb.append("<a href='?url=").append(encodeURL(url)).append("&download=pdf'>PDF</a></td>");
            sb.append("</tr>\n");
        }
        
        sb.append("</table>\n");
        sb.append("</div>\n");
        return sb.toString();
    }
    
    private String getHtmlFooter() {
        return "</div>\n" +
               "</body>\n" +
               "</html>";
    }
    
    class ScanSession {
        private String targetUrl;
        private List<ScanResult> results = new CopyOnWriteArrayList<>();
        private String status = "Pending";
        private boolean completed = false;
        private java.util.Date startTime = new java.util.Date();
        private java.util.Date endTime;
        
        public ScanSession(String targetUrl) {
            this.targetUrl = targetUrl;
        }
        
        public void addResult(ScanResult result) {
            results.add(result);
        }
        
        public void addResults(List<ScanResult> newResults) {
            results.addAll(newResults);
        }
        
        public List<ScanResult> getResults() {
            return Collections.unmodifiableList(results);
        }
        
        public String getStatus() {
            return status;
        }
        
        public void setStatus(String status) {
            this.status = status;
        }
        
        public boolean isCompleted() {
            return completed;
        }
        
        public void setCompleted(boolean completed) {
            this.completed = completed;
            if (completed) {
                this.endTime = new java.util.Date();
            }
        }
        
        public String getTargetUrl() {
            return targetUrl;
        }
        
        public java.util.Date getStartTime() {
            return startTime;
        }
        
        public java.util.Date getEndTime() {
            return endTime;
        }
    }
    
    class ScanResult {
        private String type;
        private String vulnerability;
        private String payload;
        private java.util.Date timestamp;
        
        public ScanResult(String type, String vulnerability, String payload) {
            this.type = type;
            this.vulnerability = vulnerability;
            this.payload = payload;
            this.timestamp = new java.util.Date();
        }
        
        public String getType() { return type; }
        public String getVulnerability() { return vulnerability; }
        public String getPayload() { return payload; }
        public java.util.Date getTimestamp() { return timestamp; }
    }
     
    private String escapeHtml(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#39;");
    }
    
    private String encodeURL(String url) {
        try {
            return URLEncoder.encode(url, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            return url;
        }
    }
    
    private String normalizeUrl(String url) {
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "http://" + url;
        }
        return url;
    }
    
    @Override
    public void destroy() {
        scanExecutor.shutdown();
        try {
            if (!scanExecutor.awaitTermination(60, TimeUnit.SECONDS)) {
                scanExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            scanExecutor.shutdownNow();
        }
    }
}