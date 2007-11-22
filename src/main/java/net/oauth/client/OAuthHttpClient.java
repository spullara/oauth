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
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.oauth.OAuth;
import net.oauth.OAuthAccessor;
import net.oauth.OAuthConsumer;
import net.oauth.OAuthMessage;
import net.oauth.OAuthProblemException;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.StringRequestEntity;

/**
 * Utility methods for an OAuth client based on the Jakarta Commons HTTP client.
 * 
 * @author John Kristian
 */
public class OAuthHttpClient {

    public OAuthHttpClient(HttpClientPool clientPool) {
        this.clientPool = clientPool;
    }

    private final HttpClientPool clientPool;

    /** Get a fresh request token from the service provider. */
    public void getRequestToken(OAuthAccessor accessor) throws Exception {
        accessor.accessToken = null;
        accessor.tokenSecret = null;
        HttpMethod response = invoke(accessor,
                accessor.consumer.serviceProvider.requestTokenURL, null);
        String responseBody = response.getResponseBodyAsString();
        OAuthMessage responseMessage = getResponseMessage(response,
                responseBody);
        accessor.requestToken = responseMessage.getParameter("oauth_token");
        accessor.tokenSecret = responseMessage
                .getParameter("oauth_token_secret");
        if (accessor.requestToken == null) {
            OAuthProblemException problem = new OAuthProblemException(
                    "parameter_absent");
            problem.setParameter("oauth_parameters_absent", "oauth_token");
            problem.getParameters().putAll(getExchange(response, responseBody));
            throw problem;
        }
    }

    /**
     * Send a request to the service provider and get the response. This may be
     * a request for a token, or for access to a protected resource.
     * 
     * @return the response
     */
    public HttpMethod invoke(OAuthAccessor accessor, String url,
            Collection<? extends Map.Entry> parameters) throws Exception {
        final OAuthConsumer consumer = accessor.consumer;
        List<Map.Entry> parms;
        if (parameters == null) {
            parms = new ArrayList<Map.Entry>(6);
        } else {
            parms = new ArrayList<Map.Entry>(parameters);
        }
        Map<String, String> pMap = OAuth.newMap(parms);
        if (pMap.get("oauth_token") == null && accessor.accessToken != null) {
            parms.add(new OAuth.Parameter("oauth_token", accessor.accessToken));
        }
        if (pMap.get("oauth_consumer_key") == null) {
            parms.add(new OAuth.Parameter("oauth_consumer_key",
                    consumer.consumerKey));
        }
        String httpMethod = (String) consumer.getProperty("httpMethod");
        if (httpMethod == null) {
            httpMethod = "GET";
        }
        String signatureMethod = pMap.get("oauth_signature_method");
        if (signatureMethod == null) {
            signatureMethod = (String) consumer
                    .getProperty("oauth_signature_method");
            if (signatureMethod == null) {
                signatureMethod = "HMAC-SHA1";
            }
            parms.add(new OAuth.Parameter("oauth_signature_method",
                    signatureMethod));
        }
        parms.add(new OAuth.Parameter("oauth_timestamp", (System
                .currentTimeMillis() / 1000)
                + ""));
        parms.add(new OAuth.Parameter("oauth_nonce", System.nanoTime() + ""));
        OAuthMessage message = new OAuthMessage(httpMethod, url, parms);
        message.sign(accessor);
        String form = OAuth.formEncode(message.getParameters());
        HttpMethod method;
        if ("GET".equals(message.httpMethod)) {
            method = new GetMethod(url);
            method.setQueryString(form);
            // method.addRequestHeader("Authorization", message
            // .getAuthorizationHeader(serviceProvider.userAuthorizationURL));
            method.setFollowRedirects(false);
        } else {
            PostMethod post = new PostMethod(url);
            post.setRequestEntity(new StringRequestEntity(form,
                    OAuth.FORM_ENCODED, null));
            method = post;
        }
        clientPool.getHttpClient(new URL(method.getURI().toString()))
                .executeMethod(method);
        OAuthHttpClient.checkResponse(method);
        return method;
    }

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
        try {
            for (OAuth.Parameter p : getResponseParameters(method, responseBody)) {
                problem.put(p.getKey(), p.getValue());
            }
        } catch (Exception ignored) {
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
        return getResponseMessage(method, null);
    }

    public static OAuthMessage getResponseMessage(HttpMethod method,
            String responseBody) throws IOException {
        return new OAuthMessage(method.getName(), method.getURI().toString(),
                getResponseParameters(method, responseBody));
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
