/*
 * Copyright 2008 Sean Sullivan
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

package net.oauth.client.httpclient4;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Collection;
import java.util.Map;
import net.oauth.OAuthException;
import net.oauth.OAuthMessage;
import net.oauth.OAuthProblemException;
import net.oauth.client.OAuthClient;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.params.ClientPNames;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.impl.client.DefaultHttpClient;

/**
 * Utility methods for an OAuth client based on the <a
 * href="http://hc.apache.org">Apache HttpClient</a>.
 * 
 * @author Sean Sullivan
 */
public class OAuthHttpClient extends OAuthClient {

    private final HttpClientPool clientPool;

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
            return new DefaultHttpClient();
        }
    };

    @Override
    protected OAuthMessage invoke(String method, String url,
            Collection<? extends Map.Entry<String, String>> headers,
            InputStream body, String bodyEncoding) throws IOException,
            OAuthException {
        final boolean isDelete = DELETE.equalsIgnoreCase(method);
        final boolean isPost = POST.equalsIgnoreCase(method);
        final boolean isPut = PUT.equalsIgnoreCase(method);
        final ExcerptInputStream input = new ExcerptInputStream(body);
        HttpRequestBase httpRequest;
        if (isPost || isPut) {
            HttpEntityEnclosingRequestBase entityEnclosingMethod =
                isPost ? new HttpPost(url) : new HttpPut(url);
            if (body != null) {
                String contentLength = remove(headers, CONTENT_LENGTH);
                entityEnclosingMethod.setEntity(new InputStreamEntity(input,
                        contentLength == null ? -1 : Long.parseLong(contentLength)));
            }
            httpRequest = entityEnclosingMethod;
        } else if (isDelete) {
            httpRequest = new HttpDelete(url);
        } else {
            httpRequest = new HttpGet(url);
        }
        for (Map.Entry<String, String> header : headers) {
            httpRequest.addHeader(header.getKey(), header.getValue());
        }
        HttpClient client = clientPool.getHttpClient(new URL(httpRequest
                .getURI().toString()));
        client.getParams().setBooleanParameter(ClientPNames.HANDLE_REDIRECTS, false);
        HttpResponse httpResponse = client.execute(httpRequest);
        final OAuthMessage response = new HttpMethodResponse(httpRequest,
                httpResponse, input.getExcerpt(), bodyEncoding);
        int statusCode = httpResponse.getStatusLine().getStatusCode();
        if (statusCode != HttpStatus.SC_OK) {
            OAuthProblemException problem = new OAuthProblemException();
            problem.getParameters().putAll(response.getDump());
            throw problem;
        }
        return response;
    }

}
