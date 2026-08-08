package com.Ghost.Mode.CryptoLab;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

public class DecryptionUtility {

    private static final Logger log = LoggerFactory.getLogger(DecryptionUtility.class);
    private static final int GCM_TAG_LENGTH = 128; // bits (16 bytes)

    public static void main(String[] args) {
        try {
            log.info("🛡️ GHOST SHIELD CIPHER LAB: Initiating Decryption Sequence...");

            // =========================================================================
            // STEP 1: KEYPAIR GENERATION FOR RITIK
            // =========================================================================
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(2048);
            KeyPair ritiksKeyPair = keyPairGen.generateKeyPair();
            PublicKey ritiksPublicKey = ritiksKeyPair.getPublic();
            PrivateKey ritiksPrivateKey = ritiksKeyPair.getPrivate();

            // =========================================================================
            // STEP 2: JOHN GENERATES A SESSION KEY & ENCRYPTES IT VIA RSA
            // =========================================================================
            byte[] rawSessionKey = "ThisIsA32ByteSecretSessionKey!!!".getBytes();

            Cipher rsaEncryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaEncryptCipher.init(Cipher.ENCRYPT_MODE, ritiksPublicKey);
            byte[] encryptedSessionKeyBytes = rsaEncryptCipher.doFinal(rawSessionKey);

            String encryptedSessionKeyPayload = Base64.getEncoder().encodeToString(encryptedSessionKeyBytes);
            log.debug("📥 Payload RSA Session Key: {}...", encryptedSessionKeyPayload.substring(0, 30));

            // =========================================================================
            // STEP 3: DECRYPT THE SESSION KEY (Using Ritik's Private Key)
            // =========================================================================
            byte[] incomingSessionKeyBytes = Base64.getDecoder().decode(encryptedSessionKeyPayload);
            Cipher rsaDecryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaDecryptCipher.init(Cipher.DECRYPT_MODE, ritiksPrivateKey);

            byte[] decryptedSessionKeyBytes = rsaDecryptCipher.doFinal(incomingSessionKeyBytes);
            SecretKeySpec sessionKey = new SecretKeySpec(decryptedSessionKeyBytes, "AES");
            log.info("🔓 Step 1 Success: RSA decrypted the temporary AES Session Key successfully.");

            // =========================================================================
            // STEP 4: DYNAMIC ENCRYPTION ENGINE SIMULATION (Simulating John's device)
            // =========================================================================
            String originalSecretMessage = "Hello Ritik! This is an end-to-end secured transmission.";

            // Generate a secure, randomized 12-byte initialization vector (Standard for GCM)
            byte[] ivBytes = new byte[12];
            SecureRandom random = new SecureRandom();
            random.nextBytes(ivBytes);

            Cipher aesGcmEncryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, ivBytes);
            aesGcmEncryptCipher.init(Cipher.ENCRYPT_MODE, sessionKey, spec);

            // This builds the ciphertext AND automatically appends the 16-byte authentication tag
            byte[] rawCiphertextWithTag = aesGcmEncryptCipher.doFinal(originalSecretMessage.getBytes());

            String generatedPayloadString = "enc:aes:gcm:v1:" + Base64.getEncoder().encodeToString(rawCiphertextWithTag);
            log.info("📦 Dynamically Generated Valid Payload: {}", generatedPayloadString);

            // =========================================================================
            // STEP 5: DECRYPT THE VALID CONTENT PAYLOAD (Simulating Ritik's device)
            // =========================================================================
            String base64Ciphertext = generatedPayloadString.replace("enc:aes:gcm:v1:", "");
            byte[] ciphertextBytes = Base64.getDecoder().decode(base64Ciphertext);

            Cipher aesGcmDecryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
            aesGcmDecryptCipher.init(Cipher.DECRYPT_MODE, sessionKey, spec); // Using matching IV and key instance

            // Integrity verification passes! No AEADBadTagException thrown.
            byte[] cleartextBytes = aesGcmDecryptCipher.doFinal(ciphertextBytes);
            String plainTextMessage = new String(cleartextBytes);

            log.info("=========================================================");
            log.info("🚀 BACKEND DECRYPTED RAW TEXT METRICS REVEALED:");
            log.info("=========================================================");
            log.info("💬 Plaintext: {}", plainTextMessage);
            log.info("=========================================================");

        } catch (Exception e) {
            log.error("❌ Decryption Fault: Cryptographic signature mismatch or corrupted IV tag validation.", e);
        }
    }
}