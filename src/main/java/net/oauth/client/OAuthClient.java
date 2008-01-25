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
        Collection<OAuth.Parameter> parameters = null;
        {
            // This code supports the 'Variable Accessor Secret' extension
            // described in http://oauth.pbwiki.com/AccessorSecret
            Object accessorSecret = accessor
                    .getProperty(OAuthConsumer.ACCESSOR_SECRET);
            if (accessorSecret != null) {
                parameters = new ArrayList<OAuth.Parameter>(1);
                parameters.add(new OAuth.Parameter("oauth_accessor_secret",
                        accessorSecret.toString()));
            }
        }
        OAuthMessage response = invoke(accessor,
                accessor.consumer.serviceProvider.requestTokenURL, parameters);
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
     * Construct a request message, send it to the service provider and get the
     * response. This may be a request for a token, or for access to a protected
     * resource.
     * 
     * @return the response
     */
    public OAuthMessage invoke(OAuthAccessor accessor, String url,
            Collection<? extends Map.Entry> parameters) throws Exception {
        return invoke(accessor.newRequestMessage(null, url, parameters));
    }

    /**
     * Send a request message to the service provider and get the response. This
     * may be a request for a token, or for access to a protected resource.
     * 
     * @return the response
     */
    public abstract OAuthMessage invoke(OAuthMessage request) throws Exception;

}
