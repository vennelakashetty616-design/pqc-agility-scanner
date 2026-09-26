package com.example;

import java.security.MessageDigest;
import javax.crypto.Cipher;

public class LegacyCipher {
    public byte[] digest(byte[] body) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(body);
    }

    public Cipher cipher() throws Exception {
        return Cipher.getInstance("DESede/CBC/PKCS5Padding");
    }
}
