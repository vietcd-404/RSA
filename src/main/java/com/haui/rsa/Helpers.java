package com.haui.rsa;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.apache.poi.xwpf.extractor.XWPFWordExtractor;
import org.apache.poi.xwpf.usermodel.XWPFDocument;

import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;

public class Helpers {
    public static byte[] sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(data);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexArray = "0123456789abcdef".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

//    public static String rsaEncryptWithSha256(byte[] plain, BigInteger n, BigInteger e, int blockSize) {
//        String hashHex = bytesToHex(sha256(plain));
//        String cipherBlocks = rsaEncryptText(plain, n, e, blockSize);
//        // Output format: line1=SHA256, line2=cipher blocks
//        return "SHA256=" + hashHex + "\n" + cipherBlocks;
//    }

    public static byte[] extract(File file) throws Exception {
        String name = file.getName().toLowerCase();

        if (name.endsWith(".txt") || name.endsWith(".md") || name.endsWith(".log")) {
            return Files.readAllBytes(file.toPath());
        }

        if (name.endsWith(".xlsx")) {
            return extractExcel(file).getBytes(StandardCharsets.UTF_8);
        }

        if (name.endsWith(".docx")) {
            return extractDocx(file).getBytes(StandardCharsets.UTF_8);
        }

        if (name.endsWith(".pdf")) {
            return extractPdf(file).getBytes(StandardCharsets.UTF_8);
        }

        throw new IllegalArgumentException("Không hỗ trợ định dạng file này");
    }

    // ===== Excel =====
    private static String extractExcel(File file) throws Exception {
        StringBuilder sb = new StringBuilder();

        try (Workbook wb = new XSSFWorkbook(file)) {
            for (Sheet sheet : wb) {
                sb.append("== Sheet: ").append(sheet.getSheetName()).append(" ==\n");

                for (Row row : sheet) {
                    for (Cell cell : row) {
                        sb.append(cell.toString()).append("\t");
                    }
                    sb.append("\n");
                }
            }
        }
        return normalize(sb.toString());
    }

    // ===== PDF =====
    private static String extractPdf(File file) throws Exception {
        try (PDDocument doc = PDDocument.load(file)) {
            PDFTextStripper stripper = new PDFTextStripper();
            return normalize(stripper.getText(doc));
        }
    }

    private static String extractDocx(File file) throws Exception {
        try (var is = Files.newInputStream(file.toPath());
             var doc = new XWPFDocument(is);
             var extractor = new XWPFWordExtractor(doc)) {

            return normalize(extractor.getText());
        }
    }



    // ===== normalize =====
    private static String normalize(String s) {
        return s
                .replace("\r\n", "\n")
                .replaceAll("[ \\t]+", " ")
                .trim();
    }


}
