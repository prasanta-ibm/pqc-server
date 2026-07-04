package com.terracottatech;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class KeyStoreManager {
  private static final Logger logger = LoggerFactory.getLogger(KeyStoreManager.class);

  /**
   * Detects keystore type from file extension
   *
   * @param filePath Path to the keystore file
   * @return Detected keystore type
   */
  public String detectKeystoreType(String filePath) {
    String lowerPath = filePath.toLowerCase();

    if (lowerPath.endsWith(".p12") || lowerPath.endsWith(".pfx") || lowerPath.endsWith(".pkcs12")) {
      return "PKCS12";
    } else if (lowerPath.endsWith(".jks")) {
      return "JKS";
    } else if (lowerPath.endsWith(".jceks")) {
      return "JCEKS";
    } else if (lowerPath.endsWith(".bks")) {
      return "BKS";
    }

    // Default to PKCS12 (modern standard)
    return "PKCS12";
  }

  public KeyStore loadKeyStore(File file, String password, String keystoreType)
      throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
    KeyStore keyStore = KeyStore.getInstance(keystoreType);
    try (FileInputStream fis = new FileInputStream(file)) {
      keyStore.load(fis, password != null ? password.toCharArray() : null);
    }
    return keyStore;
  }

  /**
   * Loads a KeyStore from a file with automatic type detection
   *
   * @param filePath Path to the keystore file
   * @param password Password for the keystore
   * @return Loaded KeyStore
   * @throws Exception if keystore cannot be loaded
   */
  public KeyStore loadKeyStore(String filePath, String password) throws Exception {
    File file = new File(filePath);
    if (!file.exists()) {
      throw new FileNotFoundException("Keystore file not found: " + filePath);
    }

    // Try to detect keystore type from file extension
    String keystoreType = detectKeystoreType(filePath);

    logger.info("Attempting to load keystore from: {} with type: {}", filePath, keystoreType);

    try {
      KeyStore keyStore = loadKeyStore(file, password, keystoreType);
      logger.info("Successfully loaded keystore from: {} using type: {}", filePath, keystoreType);
      return keyStore;
    } catch (Exception e) {
      logger.warn("Failed to load keystore with type {}: {}", keystoreType, e.getMessage());
      return null;
    }
  }
}
