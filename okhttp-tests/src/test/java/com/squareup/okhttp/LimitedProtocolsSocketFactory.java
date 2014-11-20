/*
 * Copyright 2014 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.squareup.okhttp;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * An {@link SSLSocketFactory} that creates sockets using a delegate, but overrides the enabled
 * protocols for any created sockets.
 */
public class LimitedProtocolsSocketFactory extends DelegatingSSLSocketFactory {

  private final String[] enabledProtocols;

  public LimitedProtocolsSocketFactory(SSLSocketFactory delegate, String... enabledProtocols) {
    super(delegate);
    this.enabledProtocols = enabledProtocols;
  }

  @Override
  public SSLSocket createSocket(Socket s, String host, int port, boolean autoClose)
      throws IOException {
    SSLSocket socket = super.createSocket(s, host, port, autoClose);
    socket.setEnabledProtocols(enabledProtocols);
    return socket;
  }

  @Override
  public SSLSocket createSocket() throws IOException {
    SSLSocket socket = super.createSocket();
    socket.setEnabledProtocols(enabledProtocols);
    return socket;
  }

  @Override
  public SSLSocket createSocket(String host, int port) throws IOException, UnknownHostException {
    SSLSocket socket = super.createSocket(host, port);
    socket.setEnabledProtocols(enabledProtocols);
    return socket;
  }

  @Override
  public SSLSocket createSocket(String host, int port, InetAddress localHost, int localPort)
      throws IOException, UnknownHostException {
    SSLSocket socket = super.createSocket(host, port, localHost, localPort);
    socket.setEnabledProtocols(enabledProtocols);
    return socket;
  }

  @Override
  public SSLSocket createSocket(InetAddress host, int port) throws IOException {
    SSLSocket socket = super.createSocket(host, port);
    socket.setEnabledProtocols(enabledProtocols);
    return socket;
  }

  @Override
  public SSLSocket createSocket(InetAddress address, int port, InetAddress localAddress,
      int localPort) throws IOException {
    SSLSocket socket = super.createSocket(address, port, localAddress, localPort);
    socket.setEnabledProtocols(enabledProtocols);
    return socket;
  }
}
