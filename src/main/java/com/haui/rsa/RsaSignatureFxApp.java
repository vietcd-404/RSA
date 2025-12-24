package com.haui.rsa;

import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class RsaSignatureFxApp extends Application {

    // ===================== STATE (KEYGEN + SIGN) =====================
    private static class AppState {
        PublicKey publicKey;
        PrivateKey privateKey;
        String publicPem;
        String privatePem;

        boolean ready() {
            return publicKey != null && privateKey != null;
        }
    }

    private final AppState st = new AppState();

    @Override
    public void start(Stage stage) {
        TabPane tabPane = new TabPane();
        tabPane.getTabs().addAll(
                buildTabKeyGen(stage),
                buildTabSign(stage),
                buildTabVerify(stage)
        );
        tabPane.setTabClosingPolicy(TabPane.TabClosingPolicy.UNAVAILABLE);

        Scene scene = new Scene(tabPane, 740, 820);
        stage.setTitle("RSA - Chữ ký số (JavaFX)");
        stage.setScene(scene);
        stage.show();
    }

    // ===================== TAB 1: KEY GEN =====================
    private Tab buildTabKeyGen(Stage stage) {
        Tab tab = new Tab("Tạo khóa");

        VBox root = new VBox(12);
        root.setPadding(new Insets(18));
        root.setStyle("");

        Label title = new Label("TẠO THAM SỐ VÀ KHÓA");
        title.setStyle("-fx-font-size: 24px; -fx-font-weight: bold;");
        title.setMaxWidth(Double.MAX_VALUE);
        title.setAlignment(Pos.CENTER);

        ToggleGroup modeGroup = new ToggleGroup();
        RadioButton rbAuto = new RadioButton("Tự động");
        rbAuto.setToggleGroup(modeGroup);
        rbAuto.setSelected(true);

        RadioButton rbCustom = new RadioButton("Tùy chọn");
        rbCustom.setToggleGroup(modeGroup);

        ComboBox<Integer> cbKeySize = new ComboBox<>();
        cbKeySize.getItems().addAll(1024, 2048, 3072, 4096);
        cbKeySize.setValue(2048);
        cbKeySize.setPrefWidth(120);

        // ===== Row "Tự động | Kích thước khóa: | [Combo]" đẹp & thẳng hàng =====
        Label lbKeySize = new Label("Kích thước khóa:");
        lbKeySize.setMinWidth(110);     // cố định độ rộng label để không bị lệch
        lbKeySize.setPrefWidth(110);

        cbKeySize.setPrefWidth(150);
        cbKeySize.setMinWidth(150);
        cbKeySize.setMaxWidth(150);
        cbKeySize.setPrefHeight(28);

        rbAuto.setMinWidth(80);         // để chữ "Tự động" không ép layout
        rbCustom.setMinWidth(80);

        HBox autoRow = new HBox(10);
        autoRow.setAlignment(Pos.CENTER_LEFT);
        autoRow.getChildren().addAll(rbAuto, lbKeySize, cbKeySize);

        TextField tfP = new TextField();
        TextField tfQ = new TextField();
        TextField tfE = new TextField();
        tfP.setPromptText("p (số nguyên tố)");
        tfQ.setPromptText("q (số nguyên tố)");
        tfE.setPromptText("e (vd: 65537)");

        GridPane customGrid = new GridPane();
        customGrid.setHgap(10);
        customGrid.setVgap(8);
        customGrid.add(rbCustom, 0, 0);
        customGrid.add(new Label("p ="), 0, 1);
        customGrid.add(tfP, 1, 1);
        customGrid.add(new Label("q ="), 0, 2);
        customGrid.add(tfQ, 1, 2);
        customGrid.add(new Label("e ="), 0, 3);
        customGrid.add(tfE, 1, 3);

        ColumnConstraints c0 = new ColumnConstraints();
        c0.setPrefWidth(30);
        ColumnConstraints c1 = new ColumnConstraints();
        c1.setHgrow(Priority.ALWAYS);
        customGrid.getColumnConstraints().addAll(c0, c1);

        Runnable applyMode = () -> {
            boolean auto = rbAuto.isSelected();
            cbKeySize.setDisable(!auto);
            tfP.setDisable(auto);
            tfQ.setDisable(auto);
            tfE.setDisable(auto);
        };
        modeGroup.selectedToggleProperty().addListener((obs, o, n) -> applyMode.run());
        applyMode.run();

        Button btnGen = new Button("Sinh khóa");
        btnGen.setStyle("-fx-background-color: #ff9aa2; -fx-font-weight: bold;");
        btnGen.setPrefWidth(120);

        TextArea taPub = new TextArea();
        taPub.setWrapText(true);
        taPub.setPrefRowCount(7);

        TextArea taPri = new TextArea();
        taPri.setWrapText(true);
        taPri.setPrefRowCount(7);

        Button btnSavePub = new Button("Lưu khóa công khai");
        btnSavePub.setStyle("-fx-background-color: #4aa3ff; -fx-text-fill: white; -fx-font-weight: bold;");

        Button btnSavePri = new Button("Lưu khóa bí mật");
        btnSavePri.setStyle("-fx-background-color: #2ecc71; -fx-text-fill: white; -fx-font-weight: bold;");

        Button btnClear = new Button("Clear");
        btnClear.setStyle("-fx-background-color: #ff9aa2; -fx-font-weight: bold;");
        btnClear.setPrefWidth(110);

        Label status = new Label();
        status.setStyle("-fx-font-weight: bold;");

        btnGen.setOnAction(e -> {
            try {
                if (rbAuto.isSelected()) {
                    int keySize = cbKeySize.getValue();
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                    kpg.initialize(keySize, new SecureRandom());
                    KeyPair kp = kpg.generateKeyPair();
                    st.publicKey = kp.getPublic();
                    st.privateKey = kp.getPrivate();
                } else {
                    BigInteger p = parseBigInt(tfP.getText(), "p");
                    BigInteger q = parseBigInt(tfQ.getText(), "q");
                    BigInteger ee = tfE.getText().trim().isEmpty()
                            ? BigInteger.valueOf(65537)
                            : parseBigInt(tfE.getText(), "e");

                    if (!p.isProbablePrime(50)) throw new IllegalArgumentException("p không phải số nguyên tố.");
                    if (!q.isProbablePrime(50)) throw new IllegalArgumentException("q không phải số nguyên tố.");
                    if (p.equals(q)) throw new IllegalArgumentException("p và q không được trùng nhau.");

                    BigInteger n = p.multiply(q);
                    BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
                    if (!ee.gcd(phi).equals(BigInteger.ONE))
                        throw new IllegalArgumentException("e và phi(n) không nguyên tố cùng nhau (gcd != 1).");

                    BigInteger d = ee.modInverse(phi);

                    KeyFactory kf = KeyFactory.getInstance("RSA");
                    st.publicKey = kf.generatePublic(new RSAPublicKeySpec(n, ee));
                    st.privateKey = kf.generatePrivate(new RSAPrivateKeySpec(n, d));
                }

                st.publicPem = toPem("PUBLIC KEY", st.publicKey.getEncoded());
                st.privatePem = toPem("PRIVATE KEY", st.privateKey.getEncoded());

                taPub.setText(st.publicPem);
                taPri.setText(st.privatePem);
                status.setText("✅ Đã sinh khóa thành công.");
            } catch (Exception ex) {
                status.setText("❌ Lỗi: " + ex.getMessage());
                showAlert(Alert.AlertType.ERROR, "Lỗi", ex.getMessage());
            }
        });

        btnSavePub.setOnAction(e -> {
            try {
                if (st.publicPem == null || st.publicPem.isBlank()) throw new IllegalStateException("Chưa có Public Key.");
                File f = saveDialog(stage, "public_key.pem");
                if (f == null) return;
                Files.writeString(f.toPath(), st.publicPem, StandardCharsets.UTF_8);
                status.setText("✅ Đã lưu khóa công khai.");
            } catch (Exception ex) {
                status.setText("❌ Lỗi lưu public key: " + ex.getMessage());
                showAlert(Alert.AlertType.ERROR, "Lỗi", ex.getMessage());
            }
        });

        btnSavePri.setOnAction(e -> {
            try {
                if (st.privatePem == null || st.privatePem.isBlank()) throw new IllegalStateException("Chưa có Private Key.");
                File f = saveDialog(stage, "private_key.pem");
                if (f == null) return;
                Files.writeString(f.toPath(), st.privatePem, StandardCharsets.UTF_8);
                status.setText("✅ Đã lưu khóa bí mật.");
            } catch (Exception ex) {
                status.setText("❌ Lỗi lưu private key: " + ex.getMessage());
                showAlert(Alert.AlertType.ERROR, "Lỗi", ex.getMessage());
            }
        });

        btnClear.setOnAction(e -> {
            st.publicKey = null;
            st.privateKey = null;
            st.publicPem = null;
            st.privatePem = null;
            taPub.clear();
            taPri.clear();
            tfP.clear();
            tfQ.clear();
            tfE.clear();
            status.setText("");
        });

        HBox genRow = new HBox(btnGen);
        genRow.setAlignment(Pos.CENTER);

        Label lbPub = new Label("Public Key (PEM):");
        lbPub.setStyle("-fx-font-weight: bold;");
        Label lbPri = new Label("Private Key (PEM):");
        lbPri.setStyle("-fx-font-weight: bold;");

        HBox pubBtnRow = new HBox(btnSavePub);
        pubBtnRow.setAlignment(Pos.CENTER_RIGHT);

        HBox priBtnRow = new HBox(btnSavePri);
        priBtnRow.setAlignment(Pos.CENTER_RIGHT);

        HBox clearRow = new HBox(btnClear);
        clearRow.setAlignment(Pos.CENTER);

        root.getChildren().addAll(
                title,
                autoRow,
                customGrid,
                genRow,
                lbPub,
                taPub,
                pubBtnRow,
                lbPri,
                taPri,
                priBtnRow,
                clearRow,
                status
        );

        tab.setContent(root);
        return tab;
    }

    // ===================== TAB 2: SIGN =====================
    private Tab buildTabSign(Stage stage) {
        Tab tab = new Tab("Ký văn bản");

        VBox root = new VBox(12);
        root.setPadding(new Insets(18));
        root.setStyle("");

        Label title = new Label("KÝ VĂN BẢN");
        title.setStyle("-fx-font-size: 24px; -fx-font-weight: bold;");
        title.setMaxWidth(Double.MAX_VALUE);
        title.setAlignment(Pos.CENTER);

        TextField tfFile = new TextField();
        tfFile.setEditable(false);
        tfFile.setPromptText("Chọn file văn bản...");

        Button btnOpen = new Button("Mở file");
        btnOpen.setStyle("-fx-background-color: #2ecc71; -fx-font-weight: bold;");

        HBox fileRow = new HBox(10, new Label("Chọn file văn bản:"), tfFile, btnOpen);
        fileRow.setAlignment(Pos.CENTER_LEFT);
        HBox.setHgrow(tfFile, Priority.ALWAYS);

        TextArea taContent = new TextArea();
        taContent.setWrapText(true);
        taContent.setPrefRowCount(10);

        ComboBox<String> cbHash = new ComboBox<>();
        cbHash.getItems().addAll("SHA-256");
        cbHash.setValue("SHA-256");
        cbHash.setPrefWidth(120);

        HBox hashRow = new HBox(10, new Label("Thuật toán băm:"), cbHash);
        hashRow.setAlignment(Pos.CENTER_LEFT);

        Label lbSig = new Label("Nội dung chữ ký (Base64):");
        lbSig.setStyle("-fx-font-weight: bold;");

        TextArea taSig = new TextArea();
        taSig.setWrapText(true);
        taSig.setPrefRowCount(6);
        taSig.setPromptText("Chữ ký Base64...");

        Button btnSign = new Button("Ký văn bản");
        btnSign.setStyle("-fx-background-color: #2ecc71; -fx-font-weight: bold;");
        btnSign.setPrefWidth(120);

        Button btnSaveText = new Button("Lưu văn bản");
        btnSaveText.setStyle("-fx-background-color: #4aa3ff; -fx-font-weight: bold;");
        btnSaveText.setPrefWidth(120);

        Button btnSaveSig = new Button("Lưu file chữ ký");
        btnSaveSig.setStyle("-fx-background-color: #e74c3c; -fx-font-weight: bold; -fx-text-fill: white;");
        btnSaveSig.setPrefWidth(140);

        HBox btnRow = new HBox(12, btnSign, btnSaveText, btnSaveSig);
        btnRow.setAlignment(Pos.CENTER);

        Label status = new Label();
        status.setStyle("-fx-font-weight: bold;");

        final File[] selectedTextFile = {null};

        btnOpen.setOnAction(e -> {
            File f = openDialog(stage, "Chọn file văn bản", "Text", "*.txt", "*.md", "*.log", "*.*");
            if (f == null) return;
            try {
                selectedTextFile[0] = f;
                tfFile.setText(f.getAbsolutePath());
                byte[] bytes = Files.readAllBytes(f.toPath());
                taContent.setText(new String(bytes, StandardCharsets.UTF_8));
                status.setText("✅ Đã đọc file văn bản.");
            } catch (Exception ex) {
                status.setText("❌ Lỗi đọc file: " + ex.getMessage());
                showAlert(Alert.AlertType.ERROR, "Lỗi", ex.getMessage());
            }
        });

        // Nếu user gõ tay thì coi như không dùng file
        taContent.textProperty().addListener((o, ov, nv) -> selectedTextFile[0] = null);

        btnSign.setOnAction(e -> {
            try {
                ensurePrivateKey(stage);

                byte[] msgBytes;
                if (selectedTextFile[0] != null) {
                    msgBytes = Files.readAllBytes(selectedTextFile[0].toPath()); // chuẩn nhất
                } else {
                    // normalize newline để consistent
                    String normalized = taContent.getText().replace("\r\n", "\n");
                    msgBytes = normalized.getBytes(StandardCharsets.UTF_8);
                }

                if (msgBytes.length == 0) throw new IllegalStateException("Nội dung văn bản rỗng.");

                Signature sig = Signature.getInstance("SHA256withRSA");
                sig.initSign(st.privateKey);
                sig.update(msgBytes);
                byte[] sigBytes = sig.sign();

                taSig.setText(Base64.getEncoder().encodeToString(sigBytes));
                status.setText("✅ Thành công: Đã ký văn bản.");
            } catch (Exception ex) {
                status.setText("❌ Lỗi ký: " + ex.getMessage());
                showAlert(Alert.AlertType.ERROR, "Lỗi", ex.getMessage());
            }
        });

        btnSaveText.setOnAction(e -> {
            try {
                File f = saveDialog(stage, "van_ban.txt");
                if (f == null) return;
                Files.writeString(f.toPath(), taContent.getText(), StandardCharsets.UTF_8);
                status.setText("✅ Đã lưu văn bản.");
            } catch (Exception ex) {
                status.setText("❌ Lỗi lưu văn bản: " + ex.getMessage());
                showAlert(Alert.AlertType.ERROR, "Lỗi", ex.getMessage());
            }
        });

        btnSaveSig.setOnAction(e -> {
            try {
                String b64 = taSig.getText() == null ? "" : taSig.getText().replaceAll("\\s+", "");
                if (b64.isEmpty()) throw new IllegalStateException("Chưa có chữ ký để lưu.");
                File f = saveDialog(stage, "signature.sig");
                if (f == null) return;
                Files.writeString(f.toPath(), b64, StandardCharsets.UTF_8);
                status.setText("✅ Đã lưu file chữ ký.");
            } catch (Exception ex) {
                status.setText("❌ Lỗi lưu chữ ký: " + ex.getMessage());
                showAlert(Alert.AlertType.ERROR, "Lỗi", ex.getMessage());
            }
        });

        root.getChildren().addAll(
                title,
                fileRow,
                new Label("Nội dung văn bản:"),
                taContent,
                hashRow,
                lbSig,
                taSig,
                btnRow,
                status
        );

        tab.setContent(root);
        return tab;
    }

    // ===================== TAB 3: VERIFY (FULL CONDITIONS + NO CACHE) =====================
    private Tab buildTabVerify(Stage stage) {
        Tab tab = new Tab("Xác minh");

        VBox root = new VBox(12);
        root.setPadding(new Insets(18));
        root.setStyle("");

        Label title = new Label("XÁC MINH CHỮ KÝ");
        title.setStyle("-fx-font-size: 24px; -fx-font-weight: bold;");
        title.setMaxWidth(Double.MAX_VALUE);
        title.setAlignment(Pos.CENTER);

        Button btnLoadPubPem = new Button("Nhập khóa công khai (PEM)");
        btnLoadPubPem.setStyle("-fx-background-color: #ff9aa2; -fx-font-weight: bold;");

        Button btnLoadText = new Button("Đọc nội dung văn bản");
        btnLoadText.setStyle("-fx-background-color: #ffe066; -fx-font-weight: bold;");

        HBox topRow = new HBox(12, btnLoadPubPem, btnLoadText);
        topRow.setAlignment(Pos.CENTER);

        TextArea taPem = new TextArea();
        taPem.setWrapText(true);
        taPem.setPrefRowCount(6);
        taPem.setPromptText("Dán PUBLIC KEY PEM vào đây...");

        TextArea taText = new TextArea();
        taText.setWrapText(true);
        taText.setPrefRowCount(10);
        taText.setPromptText("Nội dung văn bản cần xác minh...");

        Button btnLoadSig = new Button("Đọc file chữ ký");
        btnLoadSig.setStyle("-fx-background-color: #ff9aa2; -fx-font-weight: bold;");
        btnLoadSig.setMaxWidth(Double.MAX_VALUE);

        TextArea taSig = new TextArea();
        taSig.setWrapText(true);
        taSig.setPrefRowCount(4);
        taSig.setPromptText("Dán chữ ký Base64 vào đây...");

        Button btnVerify = new Button("Xác Minh");
        btnVerify.setStyle("-fx-background-color: #2ecc71; -fx-font-weight: bold;");
        btnVerify.setPrefWidth(160);

        Button btnClear = new Button("Xóa toàn bộ");
        btnClear.setStyle("-fx-background-color: #e74c3c; -fx-text-fill: white; -fx-font-weight: bold;");
        btnClear.setPrefWidth(160);

        VBox actionBox = new VBox(10, btnVerify, btnClear);
        actionBox.setAlignment(Pos.CENTER);

        Label info = new Label();
        info.setStyle("-fx-font-size: 12px; -fx-font-style: italic;");
        info.setMaxWidth(Double.MAX_VALUE);
        info.setAlignment(Pos.CENTER);

        Label status = new Label();
        status.setStyle("-fx-font-size: 14px; -fx-font-weight: bold;");
        status.setMaxWidth(Double.MAX_VALUE);
        status.setAlignment(Pos.CENTER);

        final File[] selectedTextFile = {null};

        btnLoadPubPem.setOnAction(e -> {
            File f = openDialog(stage, "Chọn Public Key (PEM)", "PEM", "*.pem", "*.*");
            if (f == null) return;
            try {
                String pem = Files.readString(f.toPath(), StandardCharsets.UTF_8);
                taPem.setText(pem);

                // parse thử để báo lỗi sớm
                PublicKey pub = loadPublicKeyFromPem(pem);
                info.setText("Key FP=" + fingerprint6(pub));
                status.setText("✅ Đã nạp khóa công khai.");
            } catch (Exception ex) {
                info.setText("");
                status.setText("❌ Lỗi nạp public key: " + ex.getMessage());
                showAlert(Alert.AlertType.ERROR, "Lỗi", ex.getMessage());
            }
        });

        btnLoadText.setOnAction(e -> {
            File f = openDialog(stage, "Chọn file văn bản", "Text", "*.txt", "*.md", "*.log", "*.*");
            if (f == null) return;
            try {
                selectedTextFile[0] = f;
                byte[] bytes = Files.readAllBytes(f.toPath());
                taText.setText(new String(bytes, StandardCharsets.UTF_8));
                status.setText("✅ Đã đọc nội dung văn bản.");
            } catch (Exception ex) {
                status.setText("❌ Lỗi đọc văn bản: " + ex.getMessage());
                showAlert(Alert.AlertType.ERROR, "Lỗi", ex.getMessage());
            }
        });

        btnLoadSig.setOnAction(e -> {
            File f = openDialog(stage, "Chọn file chữ ký", "SIG", "*.sig", "*.*");
            if (f == null) return;
            try {
                String b64 = Files.readString(f.toPath(), StandardCharsets.UTF_8);
                taSig.setText(b64);
                status.setText("✅ Đã đọc file chữ ký.");
            } catch (Exception ex) {
                status.setText("❌ Lỗi đọc chữ ký: " + ex.getMessage());
                showAlert(Alert.AlertType.ERROR, "Lỗi", ex.getMessage());
            }
        });

        // user gõ tay thì coi như không dùng file
        taText.textProperty().addListener((o, ov, nv) -> selectedTextFile[0] = null);

        btnVerify.setOnAction(e -> {
            try {
                // ====== 1) BẮT BUỘC: PUBLIC KEY PEM ======
                String pemText = taPem.getText() == null ? "" : taPem.getText().trim();
                if (pemText.isEmpty()) throw new IllegalStateException("Thiếu khóa công khai (PEM).");

                // LUÔN parse lại mỗi lần verify (KHÔNG CACHE)
                PublicKey pub = loadPublicKeyFromPem(pemText);
                info.setText("Key FP=" + fingerprint6(pub));

                // ====== 2) BẮT BUỘC: NỘI DUNG VĂN BẢN ======
                byte[] msgBytes;
                if (selectedTextFile[0] != null) {
                    msgBytes = Files.readAllBytes(selectedTextFile[0].toPath());
                } else {
                    String text = taText.getText() == null ? "" : taText.getText();
                    text = text.replace("\r\n", "\n"); // normalize newline
                    msgBytes = text.getBytes(StandardCharsets.UTF_8);
                }
                if (msgBytes.length == 0) throw new IllegalStateException("Thiếu nội dung văn bản cần xác minh.");

                // ====== 3) BẮT BUỘC: CHỮ KÝ BASE64 ======
                String b64 = taSig.getText() == null ? "" : taSig.getText();
                b64 = b64.replaceAll("\\s+", ""); // remove spaces/newlines
                if (b64.isEmpty()) throw new IllegalStateException("Thiếu chữ ký Base64.");

                byte[] sigBytes;
                try {
                    sigBytes = Base64.getDecoder().decode(b64);
                } catch (IllegalArgumentException ex) {
                    throw new IllegalStateException("Chữ ký không đúng Base64.");
                }
                if (sigBytes.length == 0) throw new IllegalStateException("Chữ ký rỗng.");

                // ====== 4) VERIFY ======
                Signature verifier = Signature.getInstance("SHA256withRSA");
                verifier.initVerify(pub);
                verifier.update(msgBytes);
                boolean ok = verifier.verify(sigBytes);

                if (ok) {
                    status.setText("✅ Thành công, Hợp lệ");
                    showAlert(Alert.AlertType.INFORMATION, "Kết quả", "✅ Thành công, Hợp lệ");
                } else {
                    status.setText("❌ Văn bản đã bị sửa đổi, ko toàn vẹn");
                    showAlert(Alert.AlertType.WARNING, "Kết quả", "❌ Văn bản đã bị sửa đổi, ko toàn vẹn");
                }

            } catch (Exception ex) {
                status.setText("❌ Lỗi xác minh: " + ex.getMessage());
                showAlert(Alert.AlertType.ERROR, "Lỗi", ex.getMessage());
            }
        });

        btnClear.setOnAction(e -> {
            selectedTextFile[0] = null;
            taPem.clear();
            taText.clear();
            taSig.clear();
            info.setText("");
            status.setText("");
        });

        root.getChildren().addAll(
                title,
                topRow,
                taPem,
                taText,
                btnLoadSig,
                taSig,
                actionBox,
                info,
                status
        );

        tab.setContent(root);
        return tab;
    }

    // ===================== KEY LOAD FOR SIGN =====================
    private void ensurePrivateKey(Stage stage) throws Exception {
        if (st.privateKey != null) return;

        Alert ask = new Alert(Alert.AlertType.CONFIRMATION);
        ask.setTitle("Thiếu Private Key");
        ask.setHeaderText("Chưa có khóa bí mật để ký.");
        ask.setContentText("Bạn muốn chọn file private_key.pem không?");
        ButtonType yes = new ButtonType("Chọn file");
        ButtonType no = new ButtonType("Hủy", ButtonBar.ButtonData.CANCEL_CLOSE);
        ask.getButtonTypes().setAll(yes, no);

        ButtonType r = ask.showAndWait().orElse(no);
        if (r != yes) throw new IllegalStateException("Bạn chưa cung cấp Private Key.");

        File f = openDialog(stage, "Chọn Private Key (PEM)", "PEM", "*.pem", "*.*");
        if (f == null) throw new IllegalStateException("Bạn chưa chọn Private Key.");

        String pem = Files.readString(f.toPath(), StandardCharsets.UTF_8);
        st.privateKey = loadPrivateKeyFromPem(pem);
    }

    // ===================== PEM + PARSE =====================
    private static String toPem(String type, byte[] der) {
        String b64 = Base64.getEncoder().encodeToString(der);
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN ").append(type).append("-----\n");
        for (int i = 0; i < b64.length(); i += 64) {
            sb.append(b64, i, Math.min(i + 64, b64.length())).append("\n");
        }
        sb.append("-----END ").append(type).append("-----\n");
        return sb.toString();
    }

    private static byte[] fromPem(String pem) {
        if (pem == null) throw new IllegalArgumentException("PEM rỗng.");
        String normalized = pem
                .replaceAll("-----BEGIN [A-Z ]+-----", "")
                .replaceAll("-----END [A-Z ]+-----", "")
                .replaceAll("\\s", "");
        if (normalized.isEmpty()) throw new IllegalArgumentException("PEM không hợp lệ (không có Base64).");
        return Base64.getDecoder().decode(normalized);
    }

    private static PublicKey loadPublicKeyFromPem(String pem) throws Exception {
        if (!pem.contains("BEGIN PUBLIC KEY")) {
            throw new IllegalArgumentException("Sai header. Public key phải là 'BEGIN PUBLIC KEY'.");
        }
        byte[] der = fromPem(pem);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    private static PrivateKey loadPrivateKeyFromPem(String pem) throws Exception {
        if (!pem.contains("BEGIN PRIVATE KEY")) {
            throw new IllegalArgumentException("Sai header. Private key phải là 'BEGIN PRIVATE KEY'.");
        }
        byte[] der = fromPem(pem);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    private static String fingerprint6(PublicKey k) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] h = md.digest(k.getEncoded());
        return String.format("%02X%02X%02X%02X%02X%02X", h[0], h[1], h[2], h[3], h[4], h[5]);
    }

    // ===================== COMMON HELPERS =====================
    private static BigInteger parseBigInt(String s, String name) {
        String t = s == null ? "" : s.trim();
        if (t.isEmpty()) throw new IllegalArgumentException("Thiếu giá trị " + name);
        try {
            return new BigInteger(t);
        } catch (Exception ex) {
            throw new IllegalArgumentException(name + " không hợp lệ (phải là số nguyên).");
        }
    }

    private static File openDialog(Stage stage, String title, String desc, String... exts) {
        FileChooser fc = new FileChooser();
        fc.setTitle(title);
        fc.getExtensionFilters().add(new FileChooser.ExtensionFilter(desc, exts));
        return fc.showOpenDialog(stage);
    }

    private static File saveDialog(Stage stage, String defaultName) {
        FileChooser fc = new FileChooser();
        fc.setInitialFileName(defaultName);
        return fc.showSaveDialog(stage);
    }

    private static void showAlert(Alert.AlertType type, String title, String content) {
        Alert a = new Alert(type);
        a.setTitle(title);
        a.setHeaderText(null);
        a.setContentText(content);
        a.showAndWait();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
