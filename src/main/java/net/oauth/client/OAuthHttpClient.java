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
import java.util.Collection;
import java.util.Map;
import net.oauth.OAuthException;
import net.oauth.OAuthMessage;
import net.oauth.OAuthProblemException;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.ByteArrayRequestEntity;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;

/**
 * Utility methods for an OAuth client based on the Jakarta Commons HTTP client.
 * 
 * @author John Kristian
 */
public class OAuthHttpClient extends OAuthClient {

    public OAuthHttpClient(HttpClientPool clientPool) {
        this.clientPool = clientPool;
    }

    public OAuthHttpClient() {
        this(NOT_POOLED);
    }

    private static final HttpClientPool NOT_POOLED = new HttpClientPool() {
        // This trivial 'pool' simply allocates a new client every time.
        // More efficient implementations are possible.
        public HttpClient getHttpClient(URL server) {
            return new HttpClient();
        }
    };

    private final HttpClientPool clientPool;

    @Override
    protected OAuthMessage invoke(String method, String url, Collection<? extends Map.Entry<String, String>> headers, byte[] body)
        throws IOException, OAuthException
    {
        final boolean isPost = "POST".equalsIgnoreCase(method);
        HttpMethod httpMethod;
        if (isPost) {
            PostMethod post = new PostMethod(url);
            if (body != null) {
                post.setRequestEntity(new ByteArrayRequestEntity(body));
            }
            httpMethod = post;
        } else {
            httpMethod = new GetMethod(url);
        }
        httpMethod.setFollowRedirects(false);
        for (Map.Entry<String, String> header : headers) {
            httpMethod.addRequestHeader(header.getKey(), header.getValue());
        }
        HttpClient client = clientPool.getHttpClient(new URL(httpMethod
                .getURI().toString()));
        client.executeMethod(httpMethod);
        final OAuthMessage response = new HttpMethodResponse(httpMethod, body);
        int statusCode = httpMethod.getStatusCode();
        if (statusCode != HttpStatus.SC_OK) {
            OAuthProblemException problem = new OAuthProblemException();
            problem.getParameters().putAll(response.getDump());
            throw problem;
        }
        return response;
    }

}
