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

import java.net.URL;
import java.util.Map;
import net.oauth.OAuth;
import net.oauth.OAuthMessage;
import net.oauth.OAuthProblemException;
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
public class OAuthHttpClient extends OAuthClient {

    public OAuthHttpClient(HttpClientPool clientPool) {
        this.clientPool = clientPool;
    }

    private final HttpClientPool clientPool;

    /** Send a message to the service provider and get the response. */
    @Override
    public OAuthMessage invoke(OAuthMessage message) throws Exception {
        HttpMethod method;
        if ("GET".equals(message.httpMethod)) {
            String url = OAuth.addParameters(message.URL, message.getParameters());
            method = new GetMethod(url);
            // method.addRequestHeader("Authorization", message
            // .getAuthorizationHeader(serviceProvider.userAuthorizationURL));
            method.setFollowRedirects(false);
        } else {
            String form = OAuth.formEncode(message.getParameters());
            PostMethod post = new PostMethod(message.URL);
            post.setRequestEntity(new StringRequestEntity(form,
                    OAuth.FORM_ENCODED, null));
            method = post;
        }
        clientPool.getHttpClient(new URL(method.getURI().toString()))
                .executeMethod(method);
        final OAuthMessage response = new HttpMethodResponse(method);
        int statusCode = method.getStatusCode();
        if (statusCode != HttpStatus.SC_OK) {
            Map<String, Object> dump = response.getDump();
            OAuthProblemException problem = new OAuthProblemException(
                    (String) dump.get(OAuthProblemException.OAUTH_PROBLEM));
            problem.getParameters().putAll(dump);
            throw problem;
        }
        return response;
    }

}
