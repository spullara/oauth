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
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.oauth.OAuth;
import net.oauth.OAuthMessage;
import net.oauth.OAuthProblemException;

/**
 * The response part of a URLConnection, encapsulated as an OAuthMessage.
 * 
 * @author John Kristian
 */
class URLConnectionResponse extends OAuthResponseMessage {

    /**
     * Construct an OAuthMessage from the HTTP response, including parameters
     * from OAuth WWW-Authenticate headers and the body. The header parameters
     * come first, followed by the ones from the response body.
     */
    public URLConnectionResponse(OAuthMessage request, String requestHeaders,
            URLConnection connection) throws IOException {
        super(request.method, request.URL);
        this.requestHeaders = requestHeaders;
        this.connection = connection;
        List<String> wwwAuthHeaders = connection.getHeaderFields().get(
                "WWW-Authenticate");
        if (wwwAuthHeaders != null) {
            for (String header : wwwAuthHeaders) {
                this.decodeWWWAuthenticate(header);
            }
        }
    }

    private final String requestHeaders;
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
        if (isDecodable(connection.getContentType())) {
            super.completeParameters();
        }
    }

    /**
     * Return a complete description of the HTTP exchange, represented by
     * strings named "URL", "HTTP request headers" and "HTTP response".
     */
    @Override
    protected void dump(Map<String, Object> into) throws IOException {
        super.dump(into);
        into.put("HTTP request headers", requestHeaders);
        {
            HttpURLConnection http = (connection instanceof HttpURLConnection) ? (HttpURLConnection) connection
                    : null;
            Integer statusCode = null;
            if (http != null) {
                statusCode = Integer.valueOf(http.getResponseCode());
                into.put(OAuthProblemException.HTTP_STATUS_CODE, statusCode);
            }
            StringBuilder response = new StringBuilder();
            List<OAuth.Parameter> responseHeaders = new ArrayList<OAuth.Parameter>();
            String value;
            for (int i = 0; (value = connection.getHeaderField(i)) != null; ++i) {
                String name = connection.getHeaderFieldKey(i);
                if (i == 0 && name != null && http != null) {
                    String firstLine = "HTTP " + statusCode;
                    String message = http.getResponseMessage();
                    if (message != null) {
                        firstLine += (" " + message);
                    }
                    response.append(firstLine).append("\n");
                    responseHeaders.add(new OAuth.Parameter(null, firstLine));
                }
                if (name != null) {
                    response.append(name).append(": ");
                    name = name.toLowerCase();
                }
                response.append(value).append("\n");
                responseHeaders.add(new OAuth.Parameter(name, value));
            }
            into.put(OAuthProblemException.RESPONSE_HEADERS, responseHeaders);
            String body = getBodyAsString();
            if (body != null) {
                response.append("\n");
                response.append(body);
            }
            into.put("HTTP response", response.toString());
        }
    }

}
