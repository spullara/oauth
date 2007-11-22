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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import net.oauth.OAuth;
import net.oauth.OAuthAccessor;
import net.oauth.OAuthConsumer;
import net.oauth.OAuthMessage;
import net.oauth.OAuthProblemException;

/**
 * Utility methods for an OAuth client.
 * 
 * @author John Kristian
 */
public abstract class OAuthClient {

    /** Get a fresh request token from the service provider. */
    public void getRequestToken(OAuthAccessor accessor) throws Exception {
        accessor.accessToken = null;
        accessor.tokenSecret = null;
        OAuthMessage response = invoke(accessor,
                accessor.consumer.serviceProvider.requestTokenURL, null);
        accessor.requestToken = response.getParameter("oauth_token");
        accessor.tokenSecret = response.getParameter("oauth_token_secret");
        if (accessor.requestToken == null) {
            OAuthProblemException problem = new OAuthProblemException(
                    "parameter_absent");
            problem.setParameter("oauth_parameters_absent", "oauth_token");
            problem.getParameters().putAll(response.getDump());
            throw problem;
        }
    }

    /**
     * Send a request to the service provider and get the response. This may be
     * a request for a token, or for access to a protected resource.
     * 
     * @return the response
     */
    public OAuthMessage invoke(OAuthAccessor accessor, String url,
            Collection<? extends Map.Entry> parameters) throws Exception {
        return invoke(newRequestMessage(accessor, url, parameters));
    }

    // TODO: move this method to OAuthMessage?
    private static OAuthMessage newRequestMessage(OAuthAccessor accessor,
            String url, Collection<? extends Map.Entry> parameters)
            throws Exception {
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
        return message;
    }

    /** Send a message to the service provider and get the response. */
    protected abstract OAuthMessage invoke(OAuthMessage message) throws Exception;

}
