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
import net.oauth.OAuthProblemException;

/**
 * The response part of a URLConnection, encapsulated as an OAuthMessage.
 * 
 * @author John Kristian
 */
public class URLConnectionResponse extends OAuthResponseMessage {

    /**
     * Construct an OAuthMessage from the HTTP response, including parameters
     * from OAuth WWW-Authenticate headers and the body. The header parameters
     * come first, followed by the ones from the response body.
     */
    public URLConnectionResponse(String method, String url,
            String requestHeaders, byte[] requestBody, String requestEncoding, URLConnection connection)
            throws IOException {
        super(method, url);
        this.requestHeaders = requestHeaders;
        this.requestBody = requestBody;
        this.requestEncoding = requestEncoding;
        this.connection = connection;
        List<String> wwwAuthHeaders = connection.getHeaderFields().get("WWW-Authenticate");
        if (wwwAuthHeaders != null) {
            for (String header : wwwAuthHeaders) {
                this.decodeWWWAuthenticate(header);
            }
        }
        contentType = connection.getContentType();
    }

    private final String requestHeaders;
    private final byte[] requestBody;
    private final String requestEncoding;
    private final URLConnection connection;
    private String bodyAsString = null;
    private final String contentType;

    @Override
    public String getContentType() {
        return contentType;
    }

    @Override
    public InputStream getBodyAsStream() throws IOException {
        if (bodyAsString == null) {
            try {
                return connection.getInputStream();
            } catch(IOException ohWell) {
                return null;
            }
        }
        return super.getBodyAsStream();
    }

    @Override
    public String getBodyAsString() throws IOException {
        if (bodyAsString == null) {
            InputStream input = getBodyAsStream();
            if (input != null) try {
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

    /** Return a complete description of the HTTP exchange. */
    @Override
    protected void dump(Map<String, Object> into) throws IOException {
        super.dump(into);
        into.put(HTTP_REQUEST_HEADERS, requestHeaders);
        {
            StringBuilder request = new StringBuilder(requestHeaders);
            request.append(EOL);
            if (requestBody != null) {
                request.append(new String(requestBody, requestEncoding));
            }
            into.put(HTTP_REQUEST, request.toString());
        }
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
                    response.append(firstLine).append(EOL);
                    responseHeaders.add(new OAuth.Parameter(null, firstLine));
                }
                if (name != null) {
                    response.append(name).append(": ");
                    name = name.toLowerCase();
                }
                response.append(value).append(EOL);
                responseHeaders.add(new OAuth.Parameter(name, value));
            }
            into.put(OAuthProblemException.RESPONSE_HEADERS, responseHeaders);
            response.append(EOL);
            String body = getBodyAsString();
            if (body != null) {
                response.append(body);
            }
            into.put(HTTP_RESPONSE, response.toString());
        }
    }

}
