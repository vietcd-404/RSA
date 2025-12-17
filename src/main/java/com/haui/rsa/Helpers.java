package com.haui.rsa;

import java.math.BigInteger;
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

    public static String rsaEncryptWithSha256(byte[] plain, BigInteger n, BigInteger e, int blockSize) {
        String hashHex = bytesToHex(sha256(plain));
        String cipherBlocks = rsaEncryptText(plain, n, e, blockSize);
        // Output format: line1=SHA256, line2=cipher blocks
        return "SHA256=" + hashHex + "\n" + cipherBlocks;
    }
}
