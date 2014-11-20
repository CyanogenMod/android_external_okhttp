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
 * An {@link javax.net.ssl.SSLSocketFactory} that delegates all method calls.
 */
public abstract class DelegatingSSLSocketFactory extends SSLSocketFactory {

  private final SSLSocketFactory delegate;

  public DelegatingSSLSocketFactory(SSLSocketFactory delegate) {
    this.delegate = delegate;
  }

  @Override
  public String[] getDefaultCipherSuites() {
    return delegate.getDefaultCipherSuites();
  }

  @Override
  public String[] getSupportedCipherSuites() {
    return delegate.getSupportedCipherSuites();
  }

  @Override
  public SSLSocket createSocket(Socket s, String host, int port, boolean autoClose)
      throws IOException {
    return (SSLSocket) delegate.createSocket(s, host, port, autoClose);
  }

  @Override
  public SSLSocket createSocket() throws IOException {
    return (SSLSocket) delegate.createSocket();
  }

  @Override
  public SSLSocket createSocket(String host, int port) throws IOException, UnknownHostException {
    return (SSLSocket) delegate.createSocket(host, port);
  }

  @Override
  public SSLSocket createSocket(String host, int port, InetAddress localHost,
      int localPort) throws IOException, UnknownHostException {
    return (SSLSocket) delegate.createSocket(host, port, localHost, localPort);
  }

  @Override
  public SSLSocket createSocket(InetAddress host, int port) throws IOException {
    return (SSLSocket) delegate.createSocket(host, port);
  }

  @Override
  public SSLSocket createSocket(InetAddress address, int port,
      InetAddress localAddress, int localPort) throws IOException {
    return (SSLSocket) delegate.createSocket(address, port, localAddress, localPort);
  }
}
