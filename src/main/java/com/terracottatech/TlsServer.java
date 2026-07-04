package com.terracottatech;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.X509Certificate;

public class TlsServer {
  private static final Logger logger = LoggerFactory.getLogger(TlsServer.class);
  private static final String PKIX_ALGORITHM = "PKIX";

  private final int port;
  private final KeyStore keyStore;
  private final KeyStore trustStore;
  private final String keyPassword;
  private final String keyAlias;

  public TlsServer(int port, KeyStore keyStore, KeyStore trustStore, String keyPassword, String keyAlias) {
    this.port = port;
    this.keyStore = keyStore;
    this.trustStore = trustStore;
    this.keyPassword = keyPassword;
    this.keyAlias = keyAlias;
  }

  public void start() throws Exception {
    // Initialize SSL context
    SSLContext sslContext = createSSLContext();
  }

  private SSLContext createSSLContext() throws Exception {
    // Create custom KeyManager that uses the specified alias
    X509KeyManager customKeyManager = createCustomKeyManager();

    // Initialize TrustManagerFactory with the truststore
    TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(PKIX_ALGORITHM);
    trustManagerFactory.init(trustStore);

    // Create and initialize SSL context
    SSLContext sslContext = SSLContext.getInstance("TLSv1.3" /*"TLS"*/);
    sslContext.init(
        new KeyManager[]{customKeyManager},
        trustManagerFactory.getTrustManagers(),
        new SecureRandom()
    );

    return sslContext;
  }

  /**
   * Creates a custom X509KeyManager that uses the specified key alias
   * Uses PKIX algorithm to support ML-DSA (post-quantum) certificates
   */
  private X509KeyManager createCustomKeyManager() throws Exception {
    // Use PKIX algorithm for ML-DSA certificate support
    KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(PKIX_ALGORITHM);
    keyManagerFactory.init(keyStore, keyPassword.toCharArray());

    // Find the X509KeyManager
    X509KeyManager defaultKeyManager = null;
    for (KeyManager km : keyManagerFactory.getKeyManagers()) {
      if (km instanceof X509KeyManager) {
        defaultKeyManager = (X509KeyManager) km;
        break;
      }
    }

    if (defaultKeyManager == null) {
      throw new IllegalStateException("No X509KeyManager found");
    }

    logAliasesInKeyStore();

    // Validate that the specified alias exists and has a valid certificate chain
    if (keyAlias != null && !keyAlias.isEmpty()) {
      checkAliasInKeyStore();

      // Validate certificate and private key exist in keystore directly
      // (Don't rely on KeyManager's getCertificateChain for self-signed certs)
      try {
        java.security.cert.Certificate cert = keyStore.getCertificate(keyAlias);
        if (cert == null) {
          logger.error("No certificate found in keystore for alias: {}", keyAlias);
          throw new IllegalArgumentException("Certificate not found for alias: " + keyAlias);
        }

        if (!(cert instanceof X509Certificate x509Cert)) {
          logger.error("Certificate is not an X509Certificate");
          throw new IllegalArgumentException("Certificate must be X509Certificate");
        }

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, keyPassword.toCharArray());

        if (privateKey == null) {
          logger.error("No private key found in keystore for alias: {}", keyAlias);
          logger.error("This may indicate an incorrect key password");
          throw new IllegalArgumentException("Private key not found for alias: " + keyAlias);
        }

        logger.info("Successfully validated key entry for alias: {}", keyAlias);
        logger.info("Certificate subject: {}", x509Cert.getSubjectX500Principal());
        logger.info("Certificate algorithm: {}", x509Cert.getPublicKey().getAlgorithm());
        logger.info("Private key algorithm: {}", privateKey.getAlgorithm());

      } catch (Exception e) {
        if (e instanceof IllegalArgumentException) {
          throw e;
        }
        logger.error("Error validating key entry", e);
        throw new IllegalStateException("Failed to validate key entry for alias: " + keyAlias, e);
      }
    }

    // Wrap it with our custom implementation that uses the specified alias
    return new AliasKeyManager(defaultKeyManager, keyAlias);
  }

  private void logAliasesInKeyStore() throws KeyStoreException {
    logger.info("Available aliases in keystore:");
    java.util.Enumeration<String> aliases = keyStore.aliases();
    while (aliases.hasMoreElements()) {
      String alias = aliases.nextElement();
      boolean isKey = keyStore.isKeyEntry(alias);
      boolean isCert = keyStore.isCertificateEntry(alias);
      logger.info("  - {} (isKeyEntry: {}, isCertificateEntry: {})", alias, isKey, isCert);
    }
  }

  private void checkAliasInKeyStore() throws KeyStoreException {
    // First check if the alias exists and what type it is
    try {
      boolean aliasExists = keyStore.containsAlias(keyAlias);
      if (!aliasExists) {
        logger.error("Alias '{}' does not exist in keystore", keyAlias);
        throw new IllegalArgumentException("Alias '" + keyAlias + "' not found in keystore");
      }

      // Check if it's a key entry (contains private key + certificate chain)
      boolean isKeyEntry = keyStore.isKeyEntry(keyAlias);
      boolean isCertEntry = keyStore.isCertificateEntry(keyAlias);

      logger.info("Alias '{}' found - isKeyEntry: {}, isCertificateEntry: {}", keyAlias, isKeyEntry, isCertEntry);

      if (!isKeyEntry) {
        logger.error("Alias '{}' is NOT a key entry (it's a certificate-only entry)", keyAlias);
        logger.error("For TLS server, you need a key entry that contains:");
        logger.error("  1. Private key");
        logger.error("  2. Certificate chain");
        logger.error("Certificate-only entries cannot be used for server authentication.");
        throw new IllegalArgumentException(
            "Alias '" + keyAlias + "' is a certificate entry, not a key entry. " +
                "Server requires a key entry with private key and certificate chain."
        );
      }
    } catch (Exception e) {
      if (e instanceof IllegalArgumentException) {
        throw e;
      }
      logger.error("Error checking keystore alias", e);
      throw new IllegalStateException("Failed to validate keystore alias: " + keyAlias, e);
    }
  }
  /**
   * Custom X509KeyManager that always uses a specific alias
   */
  private record AliasKeyManager(X509KeyManager delegate, String alias) implements X509KeyManager {
    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
      // Always return our specified alias if it's valid for the key type
      if (alias != null && !alias.isEmpty()) {
        X509Certificate[] chain = delegate.getCertificateChain(alias);
        if (chain != null && chain.length > 0) {
          return alias;
        }
      }
      // Fallback to delegate's choice
      return delegate.chooseServerAlias(keyType, issuers, socket);
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
      return delegate.chooseClientAlias(keyType, issuers, socket);
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
      return delegate.getCertificateChain(alias);
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
      return delegate.getPrivateKey(alias);
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
      return delegate.getServerAliases(keyType, issuers);
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
      return delegate.getClientAliases(keyType, issuers);
    }
  }
}
