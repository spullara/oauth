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
import net.oauth.client.OAuthClient.ParameterStyle;
import net.oauth.http.HttpResponseMessage;
import net.unto.twitter.Api;
import net.unto.twitter.HttpManager;
import net.unto.twitter.UrlUtil;
import net.unto.twitter.UtilProtos.Url;
import net.unto.twitter.UtilProtos.Url.Parameter;

/**
 * A java-twitter builder for OAuth. Use this in place of java-twitter's
 * Api.Builder; for example
 * <code>Api twitter = new OAuthBuilder(accessor, client).build()</code>.
 */
public class OAuthBuilder extends Api.Builder {

    public static final OAuthServiceProvider TWITTER_SERVICE_PROVIDER = new OAuthServiceProvider(
            "http://twitter.com/oauth/request_token", "http://twitter.com/oauth/authorize",
            "http://twitter.com/oauth/access_token");

    public OAuthBuilder(OAuthAccessor accessor, OAuthClient client) {
        httpManager(new OAuthHttpManager(accessor, client));
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
                List<OAuth.Parameter> parameters = new ArrayList<OAuth.Parameter>();
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
                    throw new RuntimeException("Expected 200 OK. Received " + statusCode);
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
