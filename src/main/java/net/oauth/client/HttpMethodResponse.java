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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.oauth.OAuth;
import net.oauth.OAuthMessage;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpMethod;

/**
 * The response part of an HttpMethod, encapsulated as an OAuthMessage.
 * 
 * @author John Kristian
 */
class HttpMethodResponse extends OAuthMessage {

    /**
     * Construct an OAuthMessage from the HTTP response, including parameters
     * from OAuth WWW-Authenticate headers and the body. The header parameters
     * come first, followed by the ones from the response body.
     */
    public HttpMethodResponse(HttpMethod method) throws IOException {
        super(method.getName(), method.getURI().toString(), NO_PARAMETERS);
        this.method = method;
        try {
            addParameters(getResponseParameters());
        } catch (Exception ignored) {
        }
    }

    private final HttpMethod method;

    private String bodyAsString = null;

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
        {
            StringBuilder response = new StringBuilder(method.getStatusLine()
                    .toString());
            response.append("\n");
            for (Header header : method.getResponseHeaders()) {
                response.append(header.getName()).append(": ").append(
                        header.getValue()).append("\n");
            }
            String body = getBodyAsString();
            if (body != null) {
                response.append("\n");
                response.append(body);
            }
            into.put("HTTP response", response.toString());
        }
    }

    private List<OAuth.Parameter> getResponseParameters() throws IOException {
        List<OAuth.Parameter> list = new ArrayList<OAuth.Parameter>();
        for (Header header : method.getResponseHeaders("WWW-Authenticate")) {
            for (OAuth.Parameter parameter : decodeAuthorization(header
                    .getValue())) {
                if (!"realm".equalsIgnoreCase(parameter.getKey())) {
                    list.add(parameter);
                }
            }
        }
        list.addAll(OAuth.decodeForm(getBodyAsString()));
        return list;
    }

}
