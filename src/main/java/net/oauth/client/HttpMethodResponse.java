/*
 * Copyright 2007 Netflix, Inc.
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
import java.util.Map;
import net.oauth.OAuthProblemException;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpMethod;

/**
 * The response part of an HttpMethod, encapsulated as an OAuthMessage.
 * 
 * @author John Kristian
 */
class HttpMethodResponse extends OAuthResponseMessage {

    /**
     * Construct an OAuthMessage from the HTTP response, including parameters
     * from OAuth WWW-Authenticate headers and the body. The header parameters
     * come first, followed by the ones from the response body.
     */
    public HttpMethodResponse(HttpMethod method) throws IOException {
        super(method.getName(), method.getURI().toString());
        this.method = method;
        for (Header header : method.getResponseHeaders("WWW-Authenticate")) {
            decodeWWWAuthenticate(header.getValue());
        }
    }

    private final HttpMethod method;

    private String bodyAsString = null;

    @Override
    public InputStream getBodyAsStream() throws IOException {
        if (bodyAsString == null) {
            return method.getResponseBodyAsStream();
        }
        return super.getBodyAsStream();
    }

    @Override
    public String getBodyAsString() throws IOException {
        if (bodyAsString == null) {
            bodyAsString = method.getResponseBodyAsString();
        }
        return bodyAsString;
    }

    /**
     * Return a complete description of the HTTP exchange, represented by
     * strings named "URL", "HTTP request headers" and "HTTP response".
     */
    @Override
    protected void dump(Map<String, Object> into) throws IOException {
        super.dump(into);
        {
            StringBuilder request = new StringBuilder(method.getName());
            request.append(" ").append(method.getPath());
            String query = method.getQueryString();
            if (query != null && query.length() > 0) {
                request.append("?").append(query);
            }
            request.append("\n");
            for (Header header : method.getRequestHeaders()) {
                request.append(header.getName()).append(": ").append(
                        header.getValue()).append("\n");
            }
            into.put("HTTP request headers", request.toString());
        }
        into.put(OAuthProblemException.HTTP_STATUS_CODE, //
                new Integer(method.getStatusCode()));
        {
            StringBuilder response = new StringBuilder(method.getStatusLine()
                    .toString());
            response.append("\n");
            for (Header header : method.getResponseHeaders()) {
                String name = header.getName();
                String value = header.getValue();
                response.append(name).append(": ").append(value).append("\n");
                if ("Location".equalsIgnoreCase(name)) {
                    into.put(OAuthProblemException.HTTP_LOCATION, value);
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
