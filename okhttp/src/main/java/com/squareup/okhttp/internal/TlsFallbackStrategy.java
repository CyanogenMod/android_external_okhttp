/*
 * Copyright (C) 2014 Square, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.squareup.okhttp.internal;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLProtocolException;
import javax.net.ssl.SSLSocket;

/**
 * Handles the socket protocol connection fallback strategy: When a secure socket connection fails
 * due to a handshake / protocol problem the connection may be retried with different protocols.
 * Instances are stateful and should be created and used for a single connection attempt.
 */
public class TlsFallbackStrategy {

  private final TlsConfiguration[] configurations;
  private int nextModeIndex;
  private boolean isFallbackPossible;
  private boolean isFallback;

  /** Create a new {@link TlsFallbackStrategy}. */
  public static TlsFallbackStrategy create() {
    return new TlsFallbackStrategy(TlsConfiguration.USE_DEFAULT, TlsConfiguration.SSL_V3_ONLY);
  }

  /** Use {@link #create()} */
  private TlsFallbackStrategy(TlsConfiguration... configurations) {
    this.nextModeIndex = 0;
    this.configurations = configurations;
  }

  /**
   * Configure the supplied {@link SSLSocket} to connect to the specified host using an appropriate
   * {@link TlsConfiguration}.
   *
   * @return the chosen {@link TlsConfiguration}
   * @throws IOException if the socket does not support any of the tls modes available
   */
  public TlsConfiguration configureSecureSocket(SSLSocket sslSocket, String host, Platform platform)
      throws IOException {

    TlsConfiguration tlsConfiguration = null;
    for (int i = nextModeIndex; i < configurations.length; i++) {
      if (configurations[i].isCompatible(sslSocket)) {
        tlsConfiguration = configurations[i];
        nextModeIndex = i + 1;
        break;
      }
    }

    if (tlsConfiguration == null) {
      // This may be the first time a connection has been attempted and the socket does not support
      // any the required protocols, or it may be a retry (but this socket supports fewer
      // protocols than was suggested by a prior socket).
      throw new IOException(
          "Unable to find acceptable protocols. isFallback=" + isFallback +
              ", modes=" + Arrays.toString(configurations) +
              ", supported protocols=" + Arrays.toString(sslSocket.getEnabledProtocols()));
    }

    isFallbackPossible = isFallbackPossible(sslSocket);

    tlsConfiguration.configureProtocols(sslSocket);
    platform.configureSecureSocket(sslSocket, host, isFallback);
    return tlsConfiguration;
  }

  /**
   * Reports a failure to complete a connection. Determines the next {@link TlsConfiguration} to
   * try, if any.
   *
   * @return {@code true} if the connection should be retried using
   *     {@link #configureSecureSocket(SSLSocket, String, Platform)} or {@code false} if not
   */
  public boolean connectionFailed(IOException e) {
    // Any future attempt to connect using this strategy will be a fallback attempt.
    isFallback = true;

    if (e instanceof SSLHandshakeException) {
      // If the problem was a CertificateException from the X509TrustManager,
      // do not retry.
      if (e.getCause() instanceof CertificateException) {
        return false;
      }
    }

    // TODO(nfuller): should we retry SSLProtocolExceptions at all? SSLProtocolExceptions can be
    // caused by TLS_FALLBACK_SCSV failures, which means we retry those when we probably should not.
    return ((e instanceof SSLHandshakeException || e instanceof SSLProtocolException))
        && isFallbackPossible;
  }

  /**
   * Returns {@code true} if any later {@link TlsConfiguration} in the fallback strategy looks
   * possible based on the supplied {@link SSLSocket}. It assumes that a future socket will have the
   * same capabilities as the supplied socket.
   */
  private boolean isFallbackPossible(SSLSocket socket) {
    for (int i = nextModeIndex; i < configurations.length; i++) {
      if (configurations[i].isCompatible(socket)) {
        return true;
      }
    }
    return false;
  }
}
