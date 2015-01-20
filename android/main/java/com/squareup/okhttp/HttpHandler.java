/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.squareup.okhttp;

import java.io.IOException;
import java.net.Proxy;
import java.net.ResponseCache;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;

public class HttpHandler extends URLStreamHandler {

    private final ConfigAwareConnectionPool configAwareConnectionPool =
            ConfigAwareConnectionPool.getInstance();

    @Override protected URLConnection openConnection(URL url) throws IOException {
        return newOkUrlFactory(null /* proxy */).open(url);
    }

    @Override protected URLConnection openConnection(URL url, Proxy proxy) throws IOException {
        if (url == null || proxy == null) {
            throw new IllegalArgumentException("url == null || proxy == null");
        }
        return newOkUrlFactory(proxy).open(url);
    }

    @Override protected int getDefaultPort() {
        return 80;
    }

    protected OkUrlFactory newOkUrlFactory(Proxy proxy) {
        OkUrlFactory okUrlFactory = createHttpOkUrlFactory(proxy);
        okUrlFactory.client().setConnectionPool(configAwareConnectionPool.get());
        return okUrlFactory;
    }

    /**
     * Creates an OkHttpClient suitable for creating {@link java.net.HttpURLConnection} instances on
     * Android.
     */
    public static OkUrlFactory createHttpOkUrlFactory(Proxy proxy) {
        OkHttpClient client = new OkHttpClient();
        client.setFollowSslRedirects(false);
        if (proxy != null) {
            client.setProxy(proxy);
        }

        // Explicitly set the response cache.
        OkUrlFactory okUrlFactory = new OkUrlFactory(client);
        ResponseCache responseCache = ResponseCache.getDefault();
        if (responseCache != null) {
            AndroidInternal.setResponseCache(okUrlFactory, responseCache);
        }
        return okUrlFactory;
    }

}
