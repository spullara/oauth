/*
 * Copyright 2007, 2008 Netflix, Inc.
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
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import net.oauth.OAuth;
import net.oauth.OAuthAccessor;
import net.oauth.OAuthConsumer;
import net.oauth.OAuthException;
import net.oauth.OAuthMessage;
import net.oauth.OAuthProblemException;

/**
 * Methods for an OAuth consumer to request tokens from a service provider.
 * <p>
 * This class can also be used to request access to protected resources, in some
 * cases. But not in all cases. For example, this class can't send OAuth
 * parameters in an HTTP Authentication header.
 * <p>
 * Methods of this class don't follow redirects. When they receive a redirect
 * response, they throw an OAuthProblemException, with properties
 * HTTP_STATUS_CODE = the redirect code and the redirect URL(s) contained in
 * RESPONSE_HEADERS named 'Location'. Such a redirect can't be handled at the
 * HTTP level, if the second request must carry another OAuth signature (with
 * different parameters). For example, Google's Service Provider routinely
 * redirects requests for access to protected resources, and requires the
 * redirected request to be signed.
 * 
 * @author John Kristian
 */
public abstract class OAuthClient {

    /**
     * Get a fresh request token from the service provider.
     * 
     * @throws URISyntaxException
     */
    public void getRequestToken(OAuthAccessor accessor, String httpMethod)
    throws IOException, OAuthException, URISyntaxException {
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
        OAuthMessage response = invoke(accessor, httpMethod,
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

    public void getRequestToken(OAuthAccessor accessor)
    throws IOException, OAuthException, URISyntaxException {
        getRequestToken(accessor, null);
    }

    /**
     * Construct a request message, send it to the service provider and get the
     * response.
     * 
     * @return the response
     * @throws URISyntaxException 
     */
    public OAuthMessage invoke(OAuthAccessor accessor, String httpMethod, String url,
            Collection<? extends Map.Entry> parameters)
    throws IOException, OAuthException, URISyntaxException {
        return invoke(accessor.newRequestMessage(httpMethod, url, parameters));
    }

    public OAuthMessage invoke(OAuthAccessor accessor, String url,
            Collection<? extends Map.Entry> parameters)
    throws IOException, OAuthException, URISyntaxException {
        return invoke(accessor, null, url, parameters);
    }

    /**
     * Send a request message to the service provider and get the response.
     * 
     * @return the response
     * @throws IOException
     *                 failed to communicate with the service provider
     * @throws OAuthProblemException
     *                 a problematic response was received
     */
    public abstract OAuthMessage invoke(OAuthMessage request)
        throws IOException, OAuthException;

}
