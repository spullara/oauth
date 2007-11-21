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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.oauth.OAuth;
import net.oauth.OAuthMessage;
import net.oauth.OAuthProblemException;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.HttpStatus;

/**
 * Utility methods for an OAuth client based on the Jakarta Commons HTTP client.
 * 
 * @author John Kristian
 */
public class OAuthHttpClient {

    /**
     * Check whether a response indicates a problem.
     * 
     * @throws OAuthProblemException
     *             the response indicates a problem
     */
    public static void checkResponse(HttpMethod method) throws IOException,
            OAuthProblemException {
        int statusCode = method.getStatusCode();
        if (statusCode != HttpStatus.SC_OK) {
            Map<String, String> etc = getExchange(method, null);
            OAuthProblemException problem = new OAuthProblemException(
                    (String) etc.get(OAuthProblemException.OAUTH_PROBLEM));
            problem.getParameters().putAll(etc);
            throw problem;
        }
    }

    /**
     * Return a complete description of the HTTP exchange, represented by
     * strings named "URL", "HTTP request headers" and "HTTP response".
     */
    public static Map<String, String> getExchange(HttpMethod method,
            String responseBody) throws IOException {
        Map<String, String> problem = new HashMap<String, String>();
        problem.put("URL", method.getURI().toString());
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
            problem.put("HTTP request headers", request.toString());
        }
        {
            StringBuilder response = new StringBuilder(method.getStatusLine()
                    .toString());
            response.append("\n");
            for (Header header : method.getResponseHeaders()) {
                response.append(header.getName()).append(": ").append(
                        header.getValue()).append("\n");
            }
            if (responseBody == null) {
                responseBody = method.getResponseBodyAsString();
            }
            if (responseBody != null) {
                response.append("\n");
                response.append(responseBody);
            }
            problem.put("HTTP response", response.toString());
        }
        for (OAuth.Parameter p : getResponseParameters(method, responseBody)) {
            problem.put(p.getKey(), p.getValue());
        }
        return problem;
    }

    /**
     * Construct an OAuthMessage from the HTTP response, including parameters
     * from OAuth WWW-Authenticate headers and the body. The header parameters
     * come first, followed by the ones from the response body.
     */
    public static OAuthMessage getResponseMessage(HttpMethod method)
            throws IOException {
        return new OAuthMessage(method.getName(), method.getURI().toString(),
                getResponseParameters(method, null));
    }

    private static List<OAuth.Parameter> getResponseParameters(
            HttpMethod method, String responseBody) throws IOException {
        List<OAuth.Parameter> list = new ArrayList<OAuth.Parameter>();
        for (Header header : method.getResponseHeaders("WWW-Authenticate")) {
            for (OAuth.Parameter parameter : OAuthMessage
                    .decodeAuthorization(header.getValue())) {
                if (!"realm".equalsIgnoreCase(parameter.getKey())) {
                    list.add(parameter);
                }
            }
        }
        if (responseBody == null) {
            responseBody = method.getResponseBodyAsString();
        }
        list.addAll(OAuth.decodeForm(responseBody));
        return list;
    }

}
