/*
 * Copyright 2009 John Kristian
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

package net.oauth.client.java_twitter;

import java.util.ArrayList;
import java.util.List;
import net.oauth.OAuth;
import net.oauth.OAuthAccessor;
import net.oauth.OAuthMessage;
import net.oauth.OAuthServiceProvider;
import net.oauth.client.OAuthClient;
import net.oauth.client.OAuthResponseMessage;
import net.oauth.client.URLConnectionClient;
import net.oauth.client.OAuthClient.ParameterStyle;
import net.oauth.http.HttpResponseMessage;
import net.unto.twitter.Api;
import net.unto.twitter.HttpManager;
import net.unto.twitter.UrlUtil;
import net.unto.twitter.UtilProtos.Url;
import net.unto.twitter.UtilProtos.Url.Parameter;

/**
 * An Api builder for OAuth. Use this in place of java-twitter's Api.Builder;
 * for example
 * <code>Api twitter = new OAuthBuilder().accessor(accessor).build()</code>.
 * The username and password are unused if the accessor is set.
 */
public class OAuthBuilder extends Api.Builder {

    public static final OAuthServiceProvider TWITTER_SERVICE_PROVIDER = new OAuthServiceProvider(
            "http://twitter.com/oauth/request_token", "http://twitter.com/oauth/authorize",
            "http://twitter.com/oauth/access_token");

    private static final OAuthClient DEFAULT_CLIENT = new OAuthClient(new URLConnectionClient());

    private OAuthClient client = DEFAULT_CLIENT;
    private OAuthAccessor accessor;
    private boolean httpManagerIsStale = false;

    /*
     * This is a little tricky. One OAuthHttpManager is constructed for each
     * sequence of mutators resulting in a non-null accessor and client,
     * followed by a call to build(). httpManagerIsStale keeps track of whether
     * mutators have been called.
     */

    /** Set the OAuthAccessor for Twitter API calls. */
    public OAuthBuilder accessor(OAuthAccessor accessor) {
        this.accessor = accessor;
        mutated();
        return this;
    }

    /** Set the OAuthClient for Twitter API calls. */
    public OAuthBuilder client(OAuthClient client) {
        this.client = client;
        mutated();
        return this;
    }

    /** Set the HttpManager for Twitter API calls. */
    @Override
    public OAuthBuilder httpManager(HttpManager httpManager) {
        super.httpManager(httpManager);
        httpManagerIsStale = false;
        return this;
    }

    /** Construct an immutable Api. */
    @Override
    public Api build() {
        if (httpManagerIsStale) {
            httpManager(new OAuthHttpManager(accessor.clone(), client));
            // The clone is necessary to make the Api immutable.
        }
        return super.build();
    }

    private void mutated() {
        if (accessor == null || client == null) {
            httpManager(null);
        } else {
            httpManagerIsStale = true;
        }
    }

    private static class OAuthHttpManager implements HttpManager {

        OAuthHttpManager(OAuthAccessor accessor, OAuthClient client) {
            this.accessor = accessor;
            this.client = client;
        }

        private final OAuthAccessor accessor;
        private final OAuthClient client;

        private void setCredentials(String accessToken, String tokenSecret) {
            accessor.accessToken = accessToken;
            accessor.tokenSecret = tokenSecret;
        }

        public void clearCredentials() {
            setCredentials(null, null);
        }

        public boolean hasCredentials() {
            return (accessor.accessToken != null);
        }

        public String get(Url url) {
            return execute(OAuthMessage.GET, url);
        }

        public String post(Url url) {
            return execute(OAuthMessage.POST, url);
        }

        private String execute(String httpMethod, Url url) {
            try {
                List<OAuth.Parameter> parameters = new ArrayList<OAuth.Parameter>(url.getParametersCount());
                for (Parameter p : url.getParametersList()) {
                    parameters.add(new OAuth.Parameter(p.getName(), p.getValue()));
                }
                OAuthMessage request = new OAuthMessage(httpMethod, UrlUtil.assemble(url), parameters);
                if (hasCredentials()) {
                    request.addRequiredParameters(accessor);
                }
                OAuthResponseMessage response = client.access(request, getStyle(request));
                int statusCode = response.getHttpResponse().getStatusCode();
                if (statusCode != HttpResponseMessage.STATUS_OK) {
                    String msg = "Expected 200 OK. Received " + statusCode;
                    if (statusCode == 401) {
                        throw new SecurityException(msg);
                    }
                    throw new RuntimeException(msg);
                }
                String responseBody = response.readBodyAsString();
                if (responseBody == null) {
                    throw new RuntimeException("Expected response body, got null");
                }
                return responseBody;
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        private ParameterStyle getStyle(OAuthMessage request) {
            Object ps = accessor.consumer.getProperty(OAuthClient.PARAMETER_STYLE);
            ParameterStyle style = (ps != null) ? Enum.valueOf(ParameterStyle.class, ps.toString())
                    : (OAuthMessage.POST.equals(request.method) ? ParameterStyle.BODY : ParameterStyle.QUERY_STRING);
            return style;
        }

    }
}
