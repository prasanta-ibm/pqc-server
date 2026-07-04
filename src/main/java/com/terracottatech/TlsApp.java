package com.terracottatech;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class TlsApp {
  private static final Logger logger = LoggerFactory.getLogger(TlsApp.class);

  public void start(String configPath) throws IOException {
    Properties config = loadConfiguration(configPath);

    // Read configuration values
    int port = Integer.parseInt(config.getProperty("server.port", "8443"));

    String keyStorePath = config.getProperty("keystore.path");
    if (keyStorePath == null || keyStorePath.isEmpty()) {
      throw new IllegalArgumentException("keystore.path is required in server.properties");
    }

    String keyStorePassword = config.getProperty("keystore.password");
    if (keyStorePassword == null || keyStorePassword.isEmpty()) {
      throw new IllegalArgumentException("keystore.password is required in server.properties");
    }

    String keyPassword = config.getProperty("keystore.key.password", keyStorePassword);
    String keyAlias = config.getProperty("keystore.key.alias");
    if (keyAlias == null || keyAlias.isEmpty()) {
      throw new IllegalArgumentException("keystore.key.alias is required in server.properties");
    }

    String trustStorePath = config.getProperty("truststore.path", keyStorePath);
    String trustStorePassword = config.getProperty("truststore.password", keyStorePassword);

    logger.info("Starting TLS Server with configuration:");
    logger.info("  Port: {}\n  Keystore: {}\n  Key Alias: {}\n  Truststore: {}",
        port, keyStorePath, keyAlias, trustStorePath);
  }

  /**
   * Loads server configuration from properties file
   *
   * @param propertiesPath Path to the properties file (optional, defaults to classpath resource)
   * @return Properties object with configuration
   * @throws IOException if properties file cannot be loaded
   */
  public Properties loadConfiguration(String propertiesPath) throws IOException {
    Properties properties = new Properties();

    if (propertiesPath != null && !propertiesPath.isEmpty()) {
      // Load from file system
      try (FileInputStream fis = new FileInputStream(propertiesPath)) {
        properties.load(fis);
        System.out.println("Loaded configuration from: " + propertiesPath);
      }
    } else {
      // Load from classpath
      try (InputStream is = TlsApp.class.getClassLoader().getResourceAsStream("server.properties")) {
        if (is == null) {
          throw new IOException("server.properties not found in classpath");
        }
        properties.load(is);
        System.out.println("Loaded configuration from classpath: server.properties");
      }
    }

    return properties;
  }

  public static void main(String[] args) throws IOException {
    logger.info("Starting the PQC Server App");
  }
}
