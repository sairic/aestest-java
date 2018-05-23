package com.sairic.example;

import javafx.util.Pair;
import org.apache.commons.lang3.time.StopWatch;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class AESGCMPerformanceTest {

    public static final int AES_KEY_SIZE = 128;    // in bits
    public static final int GCM_NONCE_LENGTH = 12; // in bytes
    public static final int GCM_TAG_LENGTH = 16;   // in bytes

    SecureRandom random;
    SecretKey key;
    Integer sampleDataSize = 100000;

    List<Long> encryptionTimes = new ArrayList<>(sampleDataSize);
    List<Long> decryptionTimes = new ArrayList<>(sampleDataSize);
    List<byte[]> sampleDataList = new ArrayList<>(sampleDataSize);


    public AESGCMPerformanceTest() throws GeneralSecurityException {
        initKey();
        initEncryptData();
        executeTest();
    }



    public byte[] decryptString(byte[] cipherText, byte[] nonce) throws GeneralSecurityException {


        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        byte[] tag = new byte[GCM_TAG_LENGTH];
        cipher.updateAAD(tag);

        return cipher.doFinal(cipherText);

    }

    /** Returns the encrypted ciper + the nonce, wish JAVA had multiple return values **/
    public Pair<byte[], byte[]> encryptString(byte[] text) throws GeneralSecurityException {

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        final byte[] nonce = new byte[GCM_NONCE_LENGTH];
        random.nextBytes(nonce);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        byte[] tag = new byte[GCM_TAG_LENGTH];
        cipher.updateAAD(tag);

        return new Pair(cipher.doFinal(text), nonce);
    }

    public void executeTest() throws GeneralSecurityException {
        StopWatch stopWatch = new StopWatch();
        for(int i = 0; i < sampleDataSize; i++) {
            //System.out.println("Original Value is " + Base64.getEncoder().encodeToString(sampleDataList.get(i)));
            stopWatch.start();
            Pair<byte[], byte[]> pair = encryptString(sampleDataList.get(i));
            stopWatch.stop();
            encryptionTimes.add(stopWatch.getNanoTime());
            stopWatch.reset();
            stopWatch.start();
            byte[] originalString = decryptString(pair.getKey(), pair.getValue());
            //System.out.println("Decrypted Value is " + Base64.getEncoder().encodeToString(originalString));
            stopWatch.stop();
            decryptionTimes.add(stopWatch.getNanoTime());
            stopWatch.reset();
        }

        long totalEncryptionTime = encryptionTimes.stream().mapToLong(i -> i).sum();
        long totalDecryptionTime = decryptionTimes.stream().mapToLong(i -> i).sum();

        System.out.println("Average Encryption Time : " + totalEncryptionTime / sampleDataSize + " nanoseconds");
        System.out.println("Total Encryption Time : " + totalEncryptionTime / 1000000 + " ms");
        System.out.println("Average Decryption Time : " + totalDecryptionTime / sampleDataSize + " nanoseconds");
        System.out.println("Total Decryption Time : " + totalDecryptionTime / 1000000 + " ms");
    }

    private void initKey() throws GeneralSecurityException {
        // Initialise random and generate key
        random = SecureRandom.getInstanceStrong();
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE, random);
        key = keyGen.generateKey();
    }

    private void initEncryptData() throws GeneralSecurityException {

        for(int i = 0; i < sampleDataSize; i++) {
            byte[] sampleData = new byte[32];
            random.nextBytes(sampleData);
            sampleDataList.add(sampleData);
        }

    }

    public static void main(String ...args) {
        try {
            new AESGCMPerformanceTest();
        }catch(GeneralSecurityException gse) {
            gse.printStackTrace();
        }
    }

}
