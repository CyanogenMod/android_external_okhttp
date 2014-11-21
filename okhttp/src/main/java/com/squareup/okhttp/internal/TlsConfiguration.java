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

import java.util.Arrays;
import javax.net.ssl.SSLSocket;

/**
 * A configuration of desired secure socket protocols.
 */
public class TlsConfiguration {
  static final String SSL_V3 = "SSLv3";

  public static final TlsConfiguration USE_DEFAULT = new TlsConfiguration(null, true);

  public static final TlsConfiguration SSL_V3_ONLY =
      new TlsConfiguration(new String[] { SSL_V3 }, false /* supportsNpn */);

  // The set of all protocols. Can be null. If non-null it must have at least one item in it, which
  // must be supported. All others are considered optional.
  private final String[] protocols;
  private final boolean supportsNpn;

  /**
   * Creates a {@link TlsConfiguration} with the specified settings.
   *
   * <p>If {@code protocols} is {@code null} this means "use the default socket configuration".
   *
   * <p>If {@code protocols} in non-null it must contain at least one value. The ordering of the
   * protocols is important: the first protocol specified <em>must</em> be supported by a socket
   * for the {@link #isCompatible(javax.net.ssl.SSLSocket)} method to return {@code true}.
   * The other protocols are considered optional. {@code protocols} must not contain null values.
   */
  private TlsConfiguration(String[] protocols, boolean supportsNpn) {
    if (protocols != null && protocols.length < 1) {
      throw new IllegalArgumentException("protocols must contain at least one protocol");
    }

    this.protocols = protocols;
    this.supportsNpn = supportsNpn;
  }

  public boolean supportsNpn() {
    return supportsNpn;
  }

  /**
   * Returns {@code true} if the socket, as currently configured, supports this configuration.
   */
  public boolean isCompatible(SSLSocket socket) {
    if (protocols == null) {
      // No primary protocol means "use default".
      return true;
    }

    // We use enabled protocols here, not supported, to avoid re-enabling a protocol that has
    // been disabled. Just because something is supported does not make it desirable to use.
    String[] enabledProtocols = socket.getEnabledProtocols();
    return contains(enabledProtocols, protocols[0]);
  }

  public void configureProtocols(SSLSocket socket) {
    if (protocols != null) {
      // We use enabled protocols here, not supported, to avoid re-enabling a protocol that has
      // been disabled. Just because something is supported does not make it desirable to use.
      String[] enabledProtocols = socket.getEnabledProtocols();

      // Create an array to hold the subset of protocols that are desired, and copy across the
      // enabled protocols that intersect.
      String[] desiredProtocols = new String[protocols.length];
      int desiredIndex = 0;
      for (int protocolsIndex = 0; protocolsIndex < protocols.length; protocolsIndex++) {
        String candidateProtocol = protocols[protocolsIndex];
        if (contains(enabledProtocols, candidateProtocol)) {
          desiredProtocols[desiredIndex++] = candidateProtocol;
        } else if (desiredIndex == 0) {
          // This is checked by isCompatible.
          throw new AssertionError("primaryProtocol " + candidateProtocol + " is not supported");
        }
      }

      // Shrink the desiredProtocols array to the correct size.
      if (desiredIndex < desiredProtocols.length) {
        String[] desiredCopy = new String[desiredIndex];
        System.arraycopy(desiredProtocols, 0, desiredCopy, 0, desiredIndex);
        desiredProtocols = desiredCopy;
      }

      socket.setEnabledProtocols(desiredProtocols);
    }
  }

  @Override
  public String toString() {
    return "TlsConfiguration{" +
        "protocols=" + Arrays.toString(protocols) +
        ", supportsNpn=" + supportsNpn +
        '}';
  }

  private static <T> boolean contains(T[] array, T value) {
    for (T arrayValue : array) {
      if (value != null && value.equals(arrayValue)) {
        return true;
      }
    }
    return false;
  }

}
