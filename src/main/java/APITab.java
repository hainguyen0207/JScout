import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.io.*;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

public class APITab {
    private final JPanel panel;
    private final JTable table;
    private final DefaultTableModel model;
    private final MontoyaApi api;
    private final Set<String> seenApiKeys = new HashSet<>();
    private final List<Object[]> allRows = new ArrayList<>();
    private MyHttpHandler myHttpHandler;

    private File currentSaveFile;
    private final JLabel filePathLabel;
    private final JTextField filterField;
    private final JComboBox<String> statusCombo;
    private final JTextField searchApiField = new JTextField(15);

    private static final String PERSISTENCE_KEY = "API_JS_EXTRACTOR_PATH";

    public APITab(MontoyaApi api) {
        this.api = api;
        this.panel = new JPanel(new BorderLayout());

        model = new DefaultTableModel(new String[]{"STT", "URL", "API", "Status"}, 0);
        table = new JTable(model);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getColumnModel().getColumn(0).setPreferredWidth(40);
        table.getColumnModel().getColumn(1).setPreferredWidth(250);
        table.getColumnModel().getColumn(2).setPreferredWidth(300);
        table.getColumnModel().getColumn(3).setPreferredWidth(80);

        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(model);
        table.setRowSorter(sorter);
        sorter.setComparator(0, Comparator.comparingInt(o -> Integer.parseInt(o.toString())));

        JScrollPane scrollPane = new JScrollPane(table);

        initializeAutoFilePath();

        filePathLabel = new JLabel(currentSaveFile.getAbsolutePath());
        filePathLabel.setForeground(new Color(0, 102, 204));

        filterField = new JTextField(20);
        statusCombo = new JComboBox<>(new String[]{"Tất cả", "✅", "❌"});

        JButton filterButton = new JButton("Lọc");
        filterButton.addActionListener(e -> applyFilter());

        JButton resetButton = new JButton("Check SiteMap");
        resetButton.addActionListener(e -> resetStatuses());

        JButton exportAllButton = new JButton("Export All API");
        exportAllButton.addActionListener(e -> exportAllApi());

        JButton loadButton = new JButton("Đổi File Lưu");
        loadButton.addActionListener(e -> loadFromFile());

        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> clearTable());

        JButton searchButton = new JButton("Tìm API");
        searchButton.addActionListener(e -> searchAPI());

        JPanel pathPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        pathPanel.add(new JLabel("File lưu: "));
        pathPanel.add(filePathLabel);

        JButton exportFolderButton = new JButton("Export SiteMap Folders");
        exportFolderButton.addActionListener(e -> exportFolders());

        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        filterPanel.add(new JLabel("Lọc:"));
        filterPanel.add(filterField);
        filterPanel.add(statusCombo);
        filterPanel.add(filterButton);
        filterPanel.add(new JLabel(" | "));
        filterPanel.add(searchApiField);
        filterPanel.add(searchButton);

        JPanel topControlPanel = new JPanel(new BorderLayout());
        topControlPanel.add(pathPanel, BorderLayout.WEST);
        topControlPanel.add(filterPanel, BorderLayout.EAST);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.add(resetButton);
        buttonPanel.add(clearButton);
        buttonPanel.add(loadButton);
        buttonPanel.add(exportAllButton);
        buttonPanel.add(exportFolderButton);

        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(topControlPanel, BorderLayout.NORTH);
        topPanel.add(buttonPanel, BorderLayout.SOUTH);

        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(scrollPane, BorderLayout.CENTER);

        // Tạo Menu Chuột phải
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem copyItem = new JMenuItem("Copy API Path");

        copyItem.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row != -1) {
                int modelRow = table.convertRowIndexToModel(row);
                String apiPath = model.getValueAt(modelRow, 2).toString();
                copyToClipboard(apiPath);
            }
        });

        popupMenu.add(copyItem);

        table.setComponentPopupMenu(popupMenu);

        loadData();
        filePathLabel.setText(currentSaveFile.getAbsolutePath());
    }

    /**
     * Tự động xác định file lưu cho project.
     * Nếu project cũ -> lấy path cũ.
     * Nếu project mới -> tạo file mới trong Documents.
     */
    private void initializeAutoFilePath() {
        String savedPath = api.persistence().extensionData().getString(PERSISTENCE_KEY);

        if (savedPath != null && !savedPath.isEmpty()) {
            currentSaveFile = new File(savedPath);
        } else {
            // Tạo folder Burp_API_JS trong Documents nếu chưa có
            String userHome = System.getProperty("user.home");
            File logDir = new File(userHome + File.separator + "Documents" + File.separator + "Burp_API_JS");
            if (!logDir.exists()) logDir.mkdirs();

            // Tạo file theo thời gian thực để tránh trùng
            String timestamp = String.valueOf(System.currentTimeMillis());
            currentSaveFile = new File(logDir, "api_extract_" + timestamp + ".csv");

            // Lưu lại vào Project để lần sau mở đúng project này nó sẽ nhận ra
            api.persistence().extensionData().setString(PERSISTENCE_KEY, currentSaveFile.getAbsolutePath());
        }
    }

    public Component getComponent() {
        return panel;
    }


    public synchronized void saveData() {
        if (currentSaveFile == null) return;

        try (PrintWriter writer = new PrintWriter(new FileWriter(currentSaveFile))) {
            for (Object[] row : allRows) {
                List<String> cols = new ArrayList<>();
                for (Object val : row) {
                    // Escape dấu nháy kép cho đúng chuẩn CSV
                    String cell = (val == null) ? "" : val.toString().replace("\"", "\"\"");
                    cols.add("\"" + cell + "\"");
                }
                writer.println(String.join(",", cols));
            }
        } catch (IOException e) {
            api.logging().logToError("Lỗi saveData: " + e.getMessage());
        }
    }

    private void loadData() {
        if (currentSaveFile == null || !currentSaveFile.exists()) return;

        allRows.clear();
        seenApiKeys.clear();

        try (BufferedReader reader = new BufferedReader(new FileReader(currentSaveFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                // Tách cột xử lý dấu ngoặc kép
                String[] cols = line.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
                if (cols.length >= 4) {
                    Object[] cleaned = new Object[4];
                    for (int i = 0; i < 4; i++) {
                        cleaned[i] = cols[i].replaceAll("^\"|\"$", "").replace("\"\"", "\"");
                    }

                    // Nạp vào bộ nhớ tạm để quản lý
                    String key = cleaned[1] + "|" + cleaned[2];
                    if (!seenApiKeys.contains(key)) {
                        seenApiKeys.add(key);
                        allRows.add(cleaned);
                    }
                }
            }
            // Sau khi nạp xong allRows, gọi hàm này để vẽ lên JTable với STT mới
            SwingUtilities.invokeLater(this::applyFilter);

        } catch (IOException e) {
            api.logging().logToError("Lỗi tự động load: " + e.getMessage());
        }
    }

    private void loadFromFile() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Chọn file CSV để lưu/load cho Project này");
        fileChooser.setFileFilter(new FileNameExtensionFilter("CSV files", "csv"));

        if (fileChooser.showOpenDialog(panel) == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            this.currentSaveFile = selectedFile;

            // Cập nhật Persistence
            api.persistence().extensionData().setString(PERSISTENCE_KEY, selectedFile.getAbsolutePath());
            filePathLabel.setText(selectedFile.getAbsolutePath());

            clearTable();
            loadData();
        }
    }


    private void applyFilter() {
        model.setRowCount(0); // Xóa sạch bảng cũ trước khi vẽ

        String filterText = filterField.getText().trim().toLowerCase();
        String statusFilter = (String) statusCombo.getSelectedItem();

        int displayStt = 1; // STT ảo bắt đầu từ 1

        for (Object[] row : allRows) {
            String apiText = row[2].toString().toLowerCase();
            String status = row[3].toString();

            // Logic Lọc (Bạn có thể đổi sang chứa/không chứa tùy ý)
            boolean matchesFilter = true;
            if (!filterText.isEmpty()) {
                for (String f : filterText.split(",")) {
                    if (!f.trim().isEmpty() && apiText.contains(f.trim())) {
                        matchesFilter = false; // Đang để logic loại bỏ (Blacklist)
                        break;
                    }
                }
            }

            boolean matchesStatus = statusFilter.equals("Tất cả") || status.equals(statusFilter);

            if (matchesFilter && matchesStatus) {
                Object[] displayRow = row.clone();
                displayRow[0] = displayStt++; // Gán STT hiển thị
                model.addRow(displayRow);
            }
        }
    }

    private void searchAPI() {
        String keyword = searchApiField.getText().trim();
        model.setRowCount(0);
        for (Object[] row : allRows) {
            if (keyword.isEmpty() || row[2].toString().contains(keyword)) model.addRow(row);
        }
    }

    private void resetStatuses() {
        // Chạy trong thread riêng để không treo UI
        new Thread(() -> {
            try {
                // 1. Lấy toàn bộ URL từ SiteMap và chuẩn hóa thành Path (giảm RAM)
                Set<String> sitemapPaths = api.siteMap().requestResponses().stream().filter(item -> item.request() != null).map(item -> {
                    try {
                        // Chỉ lấy phần Path để so sánh cho nhẹ
                        return new java.net.URL(item.request().url()).getPath();
                    } catch (Exception e) {
                        return "";
                    }
                }).filter(path -> !path.isEmpty()).collect(Collectors.toSet());

                // 2. Duyệt qua danh sách API của bạn để cập nhật trạng thái
                boolean modified = false;
                for (Object[] row : allRows) {
                    String status = row[3].toString();
                    if ("❌".equals(status)) {
                        String apiPath = row[2].toString();

                        // Nếu path của API nằm trong SiteMap -> Đánh dấu ✅
                        if (sitemapPaths.contains(apiPath) || sitemapPaths.stream().anyMatch(s -> s.endsWith(apiPath))) {
                            row[3] = "✅";
                            modified = true;
                        }
                    }
                }

                if (modified) {
                    SwingUtilities.invokeLater(() -> {
                        applyFilter();
                        saveData();
                        JOptionPane.showMessageDialog(panel, "Đã cập nhật trạng thái từ SiteMap thành công!", "Thông báo", JOptionPane.INFORMATION_MESSAGE);
                    });
                } else {
                    SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(panel, "Không tìm thấy URL nào mới trong SiteMap."));
                }

            } catch (Exception e) {
                api.logging().logToError("Lỗi Reset Status: " + e.getMessage());
            }
        }).start();
    }


    private void exportAllApi() {
        try {
            String userHome = System.getProperty("user.home");
            File downloadDir = new File(userHome + File.separator + "Downloads");
            if (!downloadDir.exists()) downloadDir.mkdirs();

            File exportFile = new File(downloadDir, "api.txt");

            int rowCount = table.getRowCount();
            if (rowCount == 0) {
                JOptionPane.showMessageDialog(panel, "Bảng đang trống, không có gì để export!", "Thông báo", JOptionPane.WARNING_MESSAGE);
                return;
            }

            try (PrintWriter writer = new PrintWriter(new FileWriter(exportFile))) {
                Set<String> filteredApis = new LinkedHashSet<>();

                for (int i = 0; i < rowCount; i++) {
                    Object apiValue = table.getValueAt(i, 2);
                    if (apiValue != null) {
                        filteredApis.add(apiValue.toString());
                    }
                }

                for (String apiPath : filteredApis) {
                    writer.println(apiPath);
                }
            }

            JOptionPane.showMessageDialog(panel, "Đã export thành công " + rowCount + " API (đã lọc) ra:\n" + exportFile.getAbsolutePath(), "Export thành công", JOptionPane.INFORMATION_MESSAGE);

        } catch (IOException e) {
            api.logging().logToError("Lỗi Export: " + e.getMessage());
            JOptionPane.showMessageDialog(panel, "Lỗi khi export: " + e.getMessage(), "Lỗi", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void exportFolders() {
        new Thread(() -> {
            try {
                String[] blacklist = {"/css/", "/js/", "/images/", "/img/", "/static/", "/assets/", "/fonts/", "/media/", "/vendor/", "/node_modules/", "/scripts/", "/image/", "image-thumbnail", "logo", "/images-", "/image-", "/images_", "/image_"};

                String userHome = System.getProperty("user.home");
                File exportFile = new File(userHome + File.separator + "Downloads", "folders_in_scope.txt");

                Set<String> folderSet = new LinkedHashSet<>();

                api.siteMap().requestResponses().stream().filter(item -> item.request() != null).forEach(item -> {
                    String url = item.request().url();
                    if (api.scope().isInScope(url)) {
                        try {
                            String fullPath = new java.net.URL(url).getPath();
                            if (fullPath == null || fullPath.isEmpty() || fullPath.equals("/")) return;

                            // Nếu path là /a/b/c.php -> folder mẹ là /a/b/
                            // Nếu path là /a/b/c/ -> folder là /a/b/c/
                            int lastSlashIndex = fullPath.lastIndexOf('/');
                            String folderPath = fullPath.substring(0, lastSlashIndex + 1);

                            if (folderPath.length() > 1) {
                                String[] parts = folderPath.split("/");
                                StringBuilder sb = new StringBuilder();

                                for (String part : parts) {
                                    if (!part.isEmpty()) {
                                        sb.append("/").append(part);
                                        String currentFolder = sb.toString() + "/";

                                        boolean isNoise = false;
                                        for (String black : blacklist) {
                                            if (currentFolder.toLowerCase().contains(black)) {
                                                isNoise = true;
                                                break;
                                            }
                                        }

                                        if (!isNoise) {
                                            folderSet.add(currentFolder);
                                        }
                                    }
                                }
                            }
                        } catch (Exception ignored) {
                        }
                    }
                });

                if (folderSet.isEmpty()) {
                    SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(panel, "Không tìm thấy folder sạch nào!"));
                    return;
                }

                List<String> sortedFolders = new ArrayList<>(folderSet);
                Collections.sort(sortedFolders);
                try (PrintWriter writer = new PrintWriter(new FileWriter(exportFile))) {
                    for (String f : sortedFolders) writer.println(f);
                }

                SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(panel, "Đã export thành công ra Downloads/folders_in_scope.txt"));

            } catch (Exception e) {
                api.logging().logToError("Lỗi Export: " + e.getMessage());
            }
        }).start();
    }

    private void clearTable() {
        model.setRowCount(0);
        seenApiKeys.clear();
        allRows.clear();

        if (this.myHttpHandler != null) {
            this.myHttpHandler.clearCache();
        }

        // 3. Xóa trắng nội dung trong file CSV
        saveData();

        JOptionPane.showMessageDialog(panel, "Đã xóa toàn bộ dữ liệu và bộ nhớ đệm.");
    }

    public void setMyHttpHandler(MyHttpHandler handler) {
        this.myHttpHandler = handler;
    }

    private void copyToClipboard(String text) {
        java.awt.datatransfer.StringSelection selection = new java.awt.datatransfer.StringSelection(text);
        java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
    }

    /**
     * Thêm nhiều entry cùng lúc. Chỉ vẽ lại bảng và lưu file 1 lần cho cả batch
     * -> tránh lag khi 1 file có hàng trăm endpoint.
     * Mỗi phần tử batch: {fullUrl, apiExtracted}
     */
    public void addEntriesBatch(List<Object[]> entries) {
        boolean added = false;
        for (Object[] e : entries) {
            String fullUrl = e[0].toString();
            String apiExtracted = e[1].toString();

            String key = fullUrl + "|" + apiExtracted;
            if (seenApiKeys.contains(key)) continue;
            seenApiKeys.add(key);

            int stt = allRows.size() + 1;
            allRows.add(new Object[]{stt, fullUrl, apiExtracted, "❌"});
            added = true;
        }

        if (added) {
            // 1 lần duy nhất cho cả batch
            SwingUtilities.invokeLater(() -> {
                applyFilter();
                saveData();
            });
        }
    }
}