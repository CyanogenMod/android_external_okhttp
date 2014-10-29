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

import org.junit.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class TlsConfigurationTest {

  private static final SSLContext sslContext = SslContextBuilder.localhost();

  @Test
  public void sslV3Only() throws Exception {
    SSLSocket compatibleSocket = createSocketWithEnabledProtocols("SSLv3", "TLSv1");
    try {
      assertTrue(TlsConfiguration.SSL_V3_ONLY.isCompatible(compatibleSocket));
      TlsConfiguration.SSL_V3_ONLY.configureProtocols(compatibleSocket);
      assertEnabledProtocols(compatibleSocket, "SSLv3");
    } finally {
      compatibleSocket.close();
    }

    SSLSocket incompatibleSocket = createSocketWithEnabledProtocols("TLSv1");
    try {
      assertFalse(TlsConfiguration.SSL_V3_ONLY.isCompatible(incompatibleSocket));
    } finally {
      incompatibleSocket.close();
    }

    assertFalse(TlsConfiguration.SSL_V3_ONLY.supportsNpn());
  }

  @Test
  public void tlsV1AndBelow() throws Exception {
    SSLSocket compatibleSocket = createSocketWithEnabledProtocols("SSLv3", "TLSv1", "TLSv1.1");
    try {
      assertTrue(TlsConfiguration.TLS_V1_0_AND_BELOW.isCompatible(compatibleSocket));
      TlsConfiguration.TLS_V1_0_AND_BELOW.configureProtocols(compatibleSocket);
      assertEnabledProtocols(compatibleSocket, "TLSv1", "SSLv3");
    } finally {
      compatibleSocket.close();
    }

    compatibleSocket = createSocketWithEnabledProtocols("TLSv1", "TLSv1.1");
    try {
      assertTrue(TlsConfiguration.TLS_V1_0_AND_BELOW.isCompatible(compatibleSocket));
      TlsConfiguration.TLS_V1_0_AND_BELOW.configureProtocols(compatibleSocket);
      assertEnabledProtocols(compatibleSocket, "TLSv1");
    } finally {
      compatibleSocket.close();
    }

    SSLSocket incompatibleSocket = createSocketWithEnabledProtocols("TLSv1.1");
    try {
      assertFalse(TlsConfiguration.TLS_V1_0_AND_BELOW.isCompatible(incompatibleSocket));
    } finally {
      incompatibleSocket.close();
    }

    incompatibleSocket = createSocketWithEnabledProtocols("SSLv3");
    try {
      assertFalse(TlsConfiguration.TLS_V1_0_AND_BELOW.isCompatible(incompatibleSocket));
    } finally {
      incompatibleSocket.close();
    }

    assertTrue(TlsConfiguration.TLS_V1_0_AND_BELOW.supportsNpn());
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
