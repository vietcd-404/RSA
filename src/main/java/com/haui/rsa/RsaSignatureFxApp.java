package com.haui.rsa;

import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class RsaSignatureFxApp extends Application {


    // ===================== Shared RSA state =====================
    static class RsaState {
        BigInteger p, q, n, phi, e, d;
        int blockSizeBytes; // size mỗi block plaintext (bytes) đảm bảo < n

        boolean ready() {
            return n != null && e != null && d != null && blockSizeBytes > 0;
        }
    }

    private final RsaState st = new RsaState();

    // ===================== RSA helpers (học thuật) =====================
    private static boolean isPrime(BigInteger x) {
        return x != null && x.compareTo(BigInteger.TWO) >= 0 && x.isProbablePrime(40);
    }

    private static BigInteger pickE(BigInteger phi) {
        BigInteger e = BigInteger.valueOf(65537);
        if (e.compareTo(phi) < 0 && e.gcd(phi).equals(BigInteger.ONE)) return e;
        e = BigInteger.valueOf(3);
        while (e.compareTo(phi) < 0 && !e.gcd(phi).equals(BigInteger.ONE)) e = e.add(BigInteger.TWO);
        return e;
    }

    private static BigInteger bi(String s) {
        return new BigInteger(s.trim());
    }

    private static String toKeyLine(String name, BigInteger v) {
        return name + "=" + v.toString();
    }

    private static BigInteger parseKeyLine(List<String> lines, String name) {
        for (String line : lines) {
            String t = line.trim();
            if (t.startsWith(name + "=")) {
                return new BigInteger(t.substring((name + "=").length()).trim());
            }
        }
        return null;
    }

    // Tính blockSizeBytes theo n để chunk plaintext: m < n
    private static int calcBlockSizeBytes(BigInteger n) {
        // đảm bảo BigInteger(1, blockBytes) < n
        // blockSizeBytes = floor((bitlen(n)-1)/8)
        int bs = Math.max(1, (n.bitLength() - 1) / 8);
        return bs;
    }

    // Plaintext bytes -> list BigInteger blocks (positive)
    private static List<BigInteger> splitToBlocks(byte[] data, int blockSize) {
        List<BigInteger> blocks = new ArrayList<>();
        for (int i = 0; i < data.length; i += blockSize) {
            int len = Math.min(blockSize, data.length - i);
            byte[] chunk = new byte[len];
            System.arraycopy(data, i, chunk, 0, len);
            blocks.add(new BigInteger(1, chunk)); // positive
        }
        // handle empty input
        if (data.length == 0) blocks.add(BigInteger.ZERO);
        return blocks;
    }

    private static byte[] joinBlocksToBytes(List<byte[]> chunks) {
        int total = 0;
        for (byte[] c : chunks) total += c.length;
        byte[] out = new byte[total];
        int pos = 0;
        for (byte[] c : chunks) {
            System.arraycopy(c, 0, out, pos, c.length);
            pos += c.length;
        }
        return out;
    }

    // Encrypt: blocks m -> c = m^e mod n (output: decimal blocks separated by space)
    private static String rsaEncryptText(byte[] plain, BigInteger n, BigInteger e, int blockSize) {
        List<BigInteger> mBlocks = splitToBlocks(plain, blockSize);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < mBlocks.size(); i++) {
            BigInteger m = mBlocks.get(i);
            if (m.compareTo(n) >= 0) {
                throw new IllegalArgumentException("Block plaintext >= n (n quá nhỏ). Hãy tăng bit hoặc đổi p,q.");
            }
            BigInteger c = m.modPow(e, n);
            if (i > 0) sb.append(' ');
            sb.append(c.toString());
        }
        return sb.toString();
    }

    // Decrypt: parse decimal blocks -> m = c^d mod n -> bytes (khôi phục chunk)
    private static byte[] rsaDecryptText(String cipherText, BigInteger n, BigInteger d) {
        String ct = cipherText.trim();
        if (ct.isEmpty()) return new byte[0];

        String[] parts = ct.split("\\s+");
        List<byte[]> chunks = new ArrayList<>();

        for (String p : parts) {
            BigInteger c = new BigInteger(p);
            if (c.signum() < 0 || c.compareTo(n) >= 0) {
                throw new IllegalArgumentException("Cipher block không hợp lệ (phải 0 <= c < n).");
            }
            BigInteger m = c.modPow(d, n);
            byte[] raw = m.toByteArray();
            // BigInteger có thể thêm 0 ở đầu để giữ dấu, loại bỏ nếu có
            if (raw.length > 1 && raw[0] == 0) {
                byte[] trimmed = new byte[raw.length - 1];
                System.arraycopy(raw, 1, trimmed, 0, trimmed.length);
                raw = trimmed;
            }
            // Nếu m=0 và raw=[0], coi chunk rỗng (dành cho input rỗng)
            if (raw.length == 1 && raw[0] == 0) raw = new byte[0];
            chunks.add(raw);
        }
        return joinBlocksToBytes(chunks);
    }

    // ===================== UI =====================
    @Override
    public void start(Stage stage) {
        TabPane tabs = new TabPane();
        tabs.getTabs().add(new Tab("Sinh khóa", tabKeygen(stage)));
        tabs.getTabs().add(new Tab("Mã hóa", tabEncrypt(stage)));
        tabs.getTabs().add(new Tab("Giải mã", tabDecrypt(stage)));
        tabs.getTabs().forEach(t -> t.setClosable(false));

        Scene scene = new Scene(tabs, 980, 560);
        stage.setTitle("RSA JavaFX - Sinh khóa / Mã hóa / Giải mã (Upload/Download)");
        stage.setScene(scene);
        stage.show();
    }

    // -------- TAB 1: Keygen + save/load keys --------
    private Pane tabKeygen(Stage stage) {
        Label title = new Label("SINH KHÓA RSA");
        title.setStyle("-fx-font-size: 16px; -fx-font-weight: 700;");

        ToggleGroup tg = new ToggleGroup();
        RadioButton rbManual = new RadioButton("Tùy chọn (nhập p,q)");
        RadioButton rbAuto = new RadioButton("Ngẫu nhiên (theo số bit)");
        rbManual.setToggleGroup(tg);
        rbAuto.setToggleGroup(tg);
        rbAuto.setSelected(true);

        ComboBox<Integer> cbBits = new ComboBox<>();
        cbBits.getItems().addAll(256, 512, 1024, 2048);
        cbBits.setValue(1024);

        TextField tfP = new TextField();
        TextField tfQ = new TextField();

        TextField tfN = new TextField(); tfN.setEditable(false);
        TextField tfPhi = new TextField(); tfPhi.setEditable(false);
        TextField tfE = new TextField(); tfE.setEditable(false);
        PasswordField tfDMask = new PasswordField(); tfDMask.setEditable(false);
        TextField tfD = new TextField(); tfD.setEditable(false);

        CheckBox cbShowD = new CheckBox("Hiện d");
        tfD.setManaged(false); tfD.setVisible(false); // default ẩn
        cbShowD.setOnAction(e -> {
            boolean show = cbShowD.isSelected();
            tfD.setManaged(show); tfD.setVisible(show);
            tfDMask.setManaged(!show); tfDMask.setVisible(!show);
        });

        Button btnGen = new Button("Sinh khóa");
        Button btnSaveKeys = new Button("Tải key xuống (save)");
        Button btnLoadKeys = new Button("Đẩy key lên (load)");
        Label status = new Label();

        Runnable syncMode = () -> {
            boolean auto = rbAuto.isSelected();
            cbBits.setDisable(!auto);
            tfP.setDisable(auto);
            tfQ.setDisable(auto);
        };
        rbAuto.setOnAction(e -> syncMode.run());
        rbManual.setOnAction(e -> syncMode.run());
        syncMode.run();

        btnGen.setOnAction(e -> {
            try {
                if (rbAuto.isSelected()) {
                    int bits = cbBits.getValue();
                    SecureRandom rnd = new SecureRandom();
                    st.p = BigInteger.probablePrime(bits / 2, rnd);
                    st.q = BigInteger.probablePrime(bits / 2, rnd);
                    while (st.p.equals(st.q)) st.q = BigInteger.probablePrime(bits / 2, rnd);
                } else {
                    st.p = bi(tfP.getText());
                    st.q = bi(tfQ.getText());
                    if (!isPrime(st.p) || !isPrime(st.q)) {
                        throw new IllegalArgumentException("p và q phải là số nguyên tố.");
                    }
                }

                st.n = st.p.multiply(st.q);
                st.phi = st.p.subtract(BigInteger.ONE).multiply(st.q.subtract(BigInteger.ONE));
                st.e = pickE(st.phi);
                st.d = st.e.modInverse(st.phi);
                st.blockSizeBytes = calcBlockSizeBytes(st.n);

                tfN.setText(st.n.toString());
                tfPhi.setText(st.phi.toString());
                tfE.setText(st.e.toString());
                tfDMask.setText("********");
                tfD.setText(st.d.toString());

                status.setText("✅ Sinh khóa OK. BlockSize=" + st.blockSizeBytes + " bytes.");
            } catch (Exception ex) {
                status.setText("❌ Lỗi sinh khóa: " + ex.getMessage());
            }
        });

        btnSaveKeys.setOnAction(e -> {
            try {
                if (!st.ready()) throw new IllegalStateException("Chưa có khóa để lưu.");
                FileChooser fc = new FileChooser();
                fc.setInitialFileName("rsa_keys.txt");
                File f = fc.showSaveDialog(stage);
                if (f == null) return;

                // Lưu đủ để load lại (p,q,n,phi,e,d,blockSize)
                List<String> lines = List.of(
                        toKeyLine("p", st.p),
                        toKeyLine("q", st.q),
                        toKeyLine("n", st.n),
                        toKeyLine("phi", st.phi),
                        toKeyLine("e", st.e),
                        toKeyLine("d", st.d),
                        "blockSizeBytes=" + st.blockSizeBytes
                );
                Files.write(f.toPath(), lines, StandardCharsets.UTF_8);
                status.setText("✅ Đã tải key xuống: " + f.getName());
            } catch (Exception ex) {
                status.setText("❌ Lỗi lưu key: " + ex.getMessage());
            }
        });

        btnLoadKeys.setOnAction(e -> {
            try {
                FileChooser fc = new FileChooser();
                File f = fc.showOpenDialog(stage);
                if (f == null) return;

                List<String> lines = Files.readAllLines(f.toPath(), StandardCharsets.UTF_8);
                st.p = parseKeyLine(lines, "p");
                st.q = parseKeyLine(lines, "q");
                st.n = parseKeyLine(lines, "n");
                st.phi = parseKeyLine(lines, "phi");
                st.e = parseKeyLine(lines, "e");
                st.d = parseKeyLine(lines, "d");
                BigInteger bsb = parseKeyLine(lines, "blockSizeBytes");
                st.blockSizeBytes = (bsb != null) ? bsb.intValue() : (st.n != null ? calcBlockSizeBytes(st.n) : 0);

                if (st.n == null || st.e == null || st.d == null) {
                    throw new IllegalArgumentException("File key thiếu n/e/d.");
                }

                tfN.setText(st.n.toString());
                tfPhi.setText(st.phi != null ? st.phi.toString() : "");
                tfE.setText(st.e.toString());
                tfDMask.setText("********");
                tfD.setText(st.d.toString());

                if (rbManual.isSelected()) {
                    tfP.setText(st.p != null ? st.p.toString() : "");
                    tfQ.setText(st.q != null ? st.q.toString() : "");
                }

                status.setText("✅ Đã đẩy key lên (load). BlockSize=" + st.blockSizeBytes + " bytes.");
            } catch (Exception ex) {
                status.setText("❌ Lỗi load key: " + ex.getMessage());
            }
        });

        GridPane g = new GridPane();
        g.setHgap(12);
        g.setVgap(12);

        int r = 0;
        g.add(new HBox(16, rbAuto, new Label("Bits:"), cbBits, rbManual), 0, r, 4, 1);

        r++;
        g.add(new Label("p"), 0, r);
        g.add(tfP, 1, r);
        g.add(new Label("q"), 2, r);
        g.add(tfQ, 3, r);

        r++;
        g.add(btnGen, 0, r);

        r++;
        g.add(new Separator(), 0, r, 4, 1);

        r++;
        g.add(new Label("Khóa công khai (Public)"), 0, r, 4, 1);

        r++;
        g.add(new Label("n"), 0, r);
        g.add(tfN, 1, r, 3, 1);

        r++;
        g.add(new Label("e"), 0, r);
        g.add(tfE, 1, r, 3, 1);

        r++;
        g.add(new Label("φ(n)"), 0, r);
        g.add(tfPhi, 1, r, 3, 1);

        r++;
        g.add(new Label("Khóa bí mật (Private)"), 0, r, 4, 1);

        r++;
        g.add(new Label("d"), 0, r);
        g.add(new HBox(10, tfDMask, tfD, cbShowD), 1, r, 3, 1);

        r++;
        g.add(new HBox(10, btnSaveKeys, btnLoadKeys), 0, r, 4, 1);

        VBox root = new VBox(12, title, g, status);
        root.setPadding(new Insets(16));
        return root;
    }

    // -------- TAB 2: Encrypt + upload/download --------
    private Pane tabEncrypt(Stage stage) {
        Label title = new Label("MÃ HÓA (Encrypt)");
        title.setStyle("-fx-font-size: 16px; -fx-font-weight: 700;");

        TextArea taPlain = new TextArea();
        taPlain.setPromptText("Nhập văn bản cần mã hóa...");
        taPlain.setPrefRowCount(7);

        TextField tfPlainFile = new TextField();
        tfPlainFile.setEditable(false);
        Button btnUploadPlain = new Button("Đẩy file lên (Upload)");
        final File[] plainFile = {null};

        TextArea taCipher = new TextArea();
        taCipher.setPromptText("Ciphertext (các block số, cách nhau bằng space)...");
        taCipher.setPrefRowCount(7);

        Button btnEncrypt = new Button("Mã hóa");
        Button btnSaveCipher = new Button("Tải ciphertext xuống (Save)");
        Label status = new Label();

        btnUploadPlain.setOnAction(e -> {
            try {
                FileChooser fc = new FileChooser();
                File f = fc.showOpenDialog(stage);
                if (f == null) return;
                plainFile[0] = f;
                tfPlainFile.setText(f.getAbsolutePath());
                String content = Files.readString(f.toPath(), StandardCharsets.UTF_8);
                taPlain.setText(content);
            } catch (Exception ex) {
                status.setText("❌ Lỗi upload plaintext: " + ex.getMessage());
            }
        });

        btnEncrypt.setOnAction(e -> {
            try {
                if (!st.ready()) throw new IllegalStateException("Chưa có khóa. Sang tab 'Sinh khóa' trước.");
                byte[] plainBytes;
                if (plainFile[0] != null) {
                    plainBytes = Files.readAllBytes(plainFile[0].toPath());
                } else {
                    plainBytes = taPlain.getText().getBytes(StandardCharsets.UTF_8);
                }
                String cipher = rsaEncryptText(plainBytes, st.n, st.e, st.blockSizeBytes);
                taCipher.setText(cipher);
                status.setText("✅ Mã hóa OK. (blockSize=" + st.blockSizeBytes + " bytes)");
            } catch (Exception ex) {
                status.setText("❌ Lỗi mã hóa: " + ex.getMessage());
            }
        });

        btnSaveCipher.setOnAction(e -> {
            try {
                String cipher = taCipher.getText().trim();
                if (cipher.isEmpty()) throw new IllegalStateException("Chưa có ciphertext để lưu.");

                FileChooser fc = new FileChooser();
                fc.setInitialFileName("ciphertext.txt");
                File f = fc.showSaveDialog(stage);
                if (f == null) return;

                Files.writeString(f.toPath(), cipher, StandardCharsets.UTF_8);
                status.setText("✅ Đã tải ciphertext xuống: " + f.getName());
            } catch (Exception ex) {
                status.setText("❌ Lỗi lưu ciphertext: " + ex.getMessage());
            }
        });

        GridPane g = new GridPane();
        g.setHgap(12);
        g.setVgap(12);

        int r = 0;
        g.add(new Label("Văn bản"), 0, r);
        g.add(taPlain, 1, r, 3, 1);

        r++;
        g.add(new Label("File"), 0, r);
        g.add(tfPlainFile, 1, r, 2, 1);
        g.add(btnUploadPlain, 3, r);

        r++;
        g.add(new HBox(10, btnEncrypt, btnSaveCipher), 1, r, 3, 1);

        r++;
        g.add(new Label("Kết quả (ciphertext)"), 0, r);
        g.add(taCipher, 1, r, 3, 1);

        VBox root = new VBox(12, title, g, status);
        root.setPadding(new Insets(16));
        return root;
    }

    // -------- TAB 3: Decrypt + upload/download --------
    private Pane tabDecrypt(Stage stage) {
        Label title = new Label("GIẢI MÃ (Decrypt)");
        title.setStyle("-fx-font-size: 16px; -fx-font-weight: 700;");

        TextArea taCipher = new TextArea();
        taCipher.setPromptText("Dán ciphertext (các block số, cách nhau bằng space)...");
        taCipher.setPrefRowCount(7);

        TextField tfCipherFile = new TextField();
        tfCipherFile.setEditable(false);
        Button btnUploadCipher = new Button("Đẩy file ciphertext lên (Upload)");
        final File[] cipherFile = {null};

        TextArea taPlainOut = new TextArea();
        taPlainOut.setPromptText("Kết quả giải mã sẽ hiện ở đây...");
        taPlainOut.setPrefRowCount(7);

        Button btnDecrypt = new Button("Giải mã");
        Button btnSavePlain = new Button("Tải kết quả xuống (Save)");
        Label status = new Label();

        btnUploadCipher.setOnAction(e -> {
            try {
                FileChooser fc = new FileChooser();
                File f = fc.showOpenDialog(stage);
                if (f == null) return;
                cipherFile[0] = f;
                tfCipherFile.setText(f.getAbsolutePath());
                String cipher = Files.readString(f.toPath(), StandardCharsets.UTF_8);
                taCipher.setText(cipher);
            } catch (Exception ex) {
                status.setText("❌ Lỗi upload ciphertext: " + ex.getMessage());
            }
        });

        btnDecrypt.setOnAction(e -> {
            try {
                if (!st.ready()) throw new IllegalStateException("Chưa có khóa. Sang tab 'Sinh khóa' trước.");
                String cipherText;
                if (cipherFile[0] != null) {
                    cipherText = Files.readString(cipherFile[0].toPath(), StandardCharsets.UTF_8);
                } else {
                    cipherText = taCipher.getText();
                }

                byte[] plainBytes = rsaDecryptText(cipherText, st.n, st.d);
                String plain = new String(plainBytes, StandardCharsets.UTF_8);
                taPlainOut.setText(plain);
                status.setText("✅ Giải mã OK.");
            } catch (Exception ex) {
                status.setText("❌ Lỗi giải mã: " + ex.getMessage());
            }
        });

        btnSavePlain.setOnAction(e -> {
            try {
                String plain = taPlainOut.getText();
                FileChooser fc = new FileChooser();
                fc.setInitialFileName("plaintext.txt");
                File f = fc.showSaveDialog(stage);
                if (f == null) return;
                Files.writeString(f.toPath(), plain, StandardCharsets.UTF_8);
                status.setText("✅ Đã tải plaintext xuống: " + f.getName());
            } catch (Exception ex) {
                status.setText("❌ Lỗi lưu plaintext: " + ex.getMessage());
            }
        });

        GridPane g = new GridPane();
        g.setHgap(12);
        g.setVgap(12);

        int r = 0;
        g.add(new Label("Ciphertext"), 0, r);
        g.add(taCipher, 1, r, 3, 1);

        r++;
        g.add(new Label("File"), 0, r);
        g.add(tfCipherFile, 1, r, 2, 1);
        g.add(btnUploadCipher, 3, r);

        r++;
        g.add(new HBox(10, btnDecrypt, btnSavePlain), 1, r, 3, 1);

        r++;
        g.add(new Label("Kết quả (plaintext)"), 0, r);
        g.add(taPlainOut, 1, r, 3, 1);

        VBox root = new VBox(12, title, g, status);
        root.setPadding(new Insets(16));
        return root;
    }

    public static void main(String[] args) {
        launch(args);
    }
}

