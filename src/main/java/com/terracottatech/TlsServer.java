package com.terracottatech;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyStore;

public class TlsServer {
  private static final Logger logger = LoggerFactory.getLogger(TlsServer.class);

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
}
