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

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class TlsFallbackStrategyTest {

  private static final SSLContext sslContext = SslContextBuilder.localhost();
  private static final String[] TLSV11_TLSV10_AND_SSLV3 =
      new String[] { "TLSv1.1", "TLSv1", "SSLv3" };
  private static final String[] TLSV1_ONLY = new String[] { "TLSv1" };
  public static final SSLHandshakeException RETRYABLE_EXCEPTION = new SSLHandshakeException(
      "Simulated handshake exception");

  private TlsFallbackStrategy fallbackStrategy;
  private Platform platform;

  @Before
  public void setUp() throws Exception {
    fallbackStrategy = TlsFallbackStrategy.create();
    platform = new Platform();
  }

  @Test
  public void nonRetryableIOException() throws Exception {
    SSLSocket supportsSslV3 = createSocketWithEnabledProtocols(TLSV11_TLSV10_AND_SSLV3);
    try {
      fallbackStrategy.configureSecureSocket(supportsSslV3, "host", platform);

      boolean retry = fallbackStrategy.connectionFailed(new IOException("Non-handshake exception"));
      assertFalse(retry);
    } finally {
      supportsSslV3.close();
    }
  }

  @Test
  public void nonRetryableSSLHandshakeException() throws Exception {
    SSLSocket supportsSslV3 = createSocketWithEnabledProtocols(TLSV11_TLSV10_AND_SSLV3);
    try {
      fallbackStrategy.configureSecureSocket(supportsSslV3, "host", platform);

      SSLHandshakeException trustIssueException =
          new SSLHandshakeException("Certificate handshake exception",
              new CertificateException());
      boolean retry = fallbackStrategy.connectionFailed(trustIssueException);
      assertFalse(retry);
    } finally {
      supportsSslV3.close();
    }
  }

  @Test
  public void retryableSSLHandshakeException() throws Exception {
    SSLSocket supportsSslV3 = createSocketWithEnabledProtocols(TLSV11_TLSV10_AND_SSLV3);
    try {
      fallbackStrategy.configureSecureSocket(supportsSslV3, "host", platform);

      boolean retry = fallbackStrategy.connectionFailed(RETRYABLE_EXCEPTION);
      assertTrue(retry);
    } finally {
      supportsSslV3.close();
    }
  }

  @Test
  public void someFallbacksSupported() throws Exception {
    SSLSocket socket = createSocketWithEnabledProtocols(TLSV11_TLSV10_AND_SSLV3);
    try {
      fallbackStrategy.configureSecureSocket(socket, "host", platform);
      assertEnabledProtocols(socket, TLSV11_TLSV10_AND_SSLV3);

      boolean retry = fallbackStrategy.connectionFailed(RETRYABLE_EXCEPTION);
      assertTrue(retry);
    } finally {
      socket.close();
    }

    socket = createSocketWithEnabledProtocols(TLSV11_TLSV10_AND_SSLV3);
    try {
      fallbackStrategy.configureSecureSocket(socket, "host", platform);
      assertEnabledProtocols(socket, "TLSv1", "SSLv3");

      boolean retry = fallbackStrategy.connectionFailed(RETRYABLE_EXCEPTION);
      assertTrue(retry);
    } finally {
      socket.close();
    }

    socket = createSocketWithEnabledProtocols(TLSV11_TLSV10_AND_SSLV3);
    try {
      fallbackStrategy.configureSecureSocket(socket, "host", platform);
      assertEnabledProtocols(socket, "SSLv3");

      boolean retry = fallbackStrategy.connectionFailed(RETRYABLE_EXCEPTION);
      assertFalse(retry);
    } finally {
      socket.close();
    }
  }

  @Test
  public void sslV3NotSupported() throws Exception {
    SSLSocket socket = createSocketWithEnabledProtocols(TLSV1_ONLY);
    try {
      fallbackStrategy.configureSecureSocket(socket, "host", platform);
      assertEnabledProtocols(socket, TLSV1_ONLY);

      boolean retry = fallbackStrategy.connectionFailed(RETRYABLE_EXCEPTION);
      assertFalse(retry);
    } finally {
      socket.close();
    }
  }

  private SSLSocket createSocketWithEnabledProtocols(String... protocols) throws IOException {
    SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket();
    socket.setEnabledProtocols(protocols);
    return socket;
  }

  private static void assertEnabledProtocols(SSLSocket socket, String... required) {
    Set<String> actual = new HashSet<String>(Arrays.asList(socket.getEnabledProtocols()));
    Set<String> expected = new HashSet<String>(Arrays.asList(required));
    assertEquals(expected, actual);
  }
}
