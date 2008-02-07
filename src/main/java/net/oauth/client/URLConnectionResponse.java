/*
 * Copyright 2008 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.oauth.client;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.List;
import java.util.Map;
import net.oauth.OAuth;
import net.oauth.OAuthMessage;

/**
 * The response part of a URLConnection, encapsulated as an OAuthMessage.
 * 
 * @author John Kristian
 */
class URLConnectionResponse extends OAuthMessage {

    /**
     * Construct an OAuthMessage from the HTTP response, including parameters
     * from OAuth WWW-Authenticate headers and the body. The header parameters
     * come first, followed by the ones from the response body.
     */
    public URLConnectionResponse(OAuthMessage request, URLConnection connection)
            throws IOException {
        super(request.method, request.URL, NO_PARAMETERS);
        this.connection = connection;
        for (String header : connection.getHeaderFields().get(
                "WWW-Authenticate")) {
            for (OAuth.Parameter parameter : decodeAuthorization(header)) {
                if (!"realm".equalsIgnoreCase(parameter.getKey())) {
                    addParameter(parameter);
                }
            }
        }
    }

    private final URLConnection connection;

    private String bodyAsString = null;

    @Override
    public InputStream getBodyAsStream() throws IOException {
        if (bodyAsString == null) {
            return connection.getInputStream();
        }
        return super.getBodyAsStream();
    }

    @Override
    public String getBodyAsString() throws IOException {
        if (bodyAsString == null) {
            InputStream input = getBodyAsStream();
            try {
                String encoding = connection.getContentEncoding();
                if (encoding == null) {
                    encoding = "ISO-8859-1";
                }
                Reader reader = new InputStreamReader(input, encoding);
                StringBuilder b = new StringBuilder();
                char[] c = new char[1024];
                int len;
                while (0 < (len = reader.read(c)))
                    b.append(c, 0, len);
                bodyAsString = b.toString();
            } finally {
                input.close();
            }
        }
        return bodyAsString;
    }

    @Override
    protected void completeParameters() throws IOException {
        String contentType = connection.getContentType();
        if (contentType != null) {
            int semi = contentType.indexOf(';');
            if (semi >= 0)
                contentType = contentType.substring(0, semi);
            if (!("text/plain".equalsIgnoreCase(contentType) || OAuth.FORM_ENCODED
                    .equalsIgnoreCase(contentType))) {
                return;
            }
        }
        addParameters(OAuth.decodeForm(getBodyAsString()));
    }

    /**
     * Return a complete description of the HTTP exchange, represented by
     * strings named "URL", "HTTP request headers" and "HTTP response".
     */
    @Override
    protected void dump(Map<String, Object> into) throws IOException {
        super.dump(into);
        {
            StringBuilder request = new StringBuilder(method);
            URL url = new URL(this.URL);
            request.append(" ").append(url.getPath());
            String query = url.getQuery();
            if (query != null && query.length() > 0) {
                request.append("?").append(query);
            }
            request.append("\n");
            for (Map.Entry<String, List<String>> header : connection
                    .getRequestProperties().entrySet()) {
                String key = header.getKey();
                for (String value : header.getValue()) {
                    request.append(key).append(": ").append(value).append("\n");
                }
            }
            into.put("HTTP request headers", request.toString());
        }
        {
            StringBuilder response = new StringBuilder();
            if (connection instanceof HttpURLConnection) {
                HttpURLConnection http = (HttpURLConnection) connection;
                response.append(http.getResponseCode());
                String message = http.getResponseMessage();
                if (message != null) {
                    response.append(" ").append(message);
                }
            }
            response.append("\n");
            for (Map.Entry<String, List<String>> header : connection
                    .getHeaderFields().entrySet()) {
                String key = header.getKey();
                for (String value : header.getValue()) {
                    response.append(key).append(": ").append(value)
                            .append("\n");
                }
            }
            String body = getBodyAsString();
            if (body != null) {
                response.append("\n");
                response.append(body);
            }
            into.put("HTTP response", response.toString());
        }
    }

}
