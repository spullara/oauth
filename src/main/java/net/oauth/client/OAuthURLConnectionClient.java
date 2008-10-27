/*
 * Copyright 2008 Netflix, Inc.
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
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import net.oauth.OAuthException;
import net.oauth.OAuthMessage;
import net.oauth.OAuthProblemException;

/**
 * Utility methods for an OAuth client based on HttpURLConnection.
 * <p>
 * httpclient3.OAuthHttpClient or httpclient4.OAuthHttpClient perform better
 * than this class, as a rule; since they do things like connection pooling.
 * 
 * @author John Kristian
 */
public class OAuthURLConnectionClient extends OAuthClient {

    /** Send a message to the service provider and get the response. */
    @Override
    protected OAuthMessage invoke(String httpMethod, String urlString,
            Collection<? extends Map.Entry<String, String>> addHeaders, byte[] body)
        throws IOException, OAuthException
    {
        final URL url = new URL(urlString);
        final URLConnection connection = url.openConnection();
        connection.setDoInput(true);
        if (connection instanceof HttpURLConnection) {
            HttpURLConnection http = (HttpURLConnection) connection;
            http.setRequestMethod(httpMethod);
            http.setInstanceFollowRedirects(false);
        }
        StringBuilder headers = new StringBuilder(httpMethod);
        {
            headers.append(" ").append(url.getPath());
            String query = url.getQuery();
            if (query != null && query.length() > 0) {
                headers.append("?").append(query);
            }
            headers.append(EOL);
            for (Map.Entry<String, List<String>> header : connection
                    .getRequestProperties().entrySet()) {
                String key = header.getKey();
                for (String value : header.getValue()) {
                    headers.append(key).append(": ").append(value).append(EOL);
                }
            }
        }
        for (Map.Entry<String, String> header : addHeaders) {
            connection.setRequestProperty(header.getKey(), header.getValue());
            headers.append(header.getKey()).append(": ").append(header.getValue());
        }
        if (body != null) {
            connection.setDoOutput(true);
            OutputStream output = connection.getOutputStream();
            try {
                output.write(body);
            } finally {
                output.close();
            }
        }
        final OAuthMessage response = new URLConnectionResponse(httpMethod,
                urlString, headers.toString(), body, connection);
        if (connection instanceof HttpURLConnection) {
            HttpURLConnection http = (HttpURLConnection) connection;
            int statusCode = http.getResponseCode();
            if (statusCode != HttpURLConnection.HTTP_OK) {
                OAuthProblemException problem = new OAuthProblemException();
                problem.getParameters().putAll(response.getDump());
                throw problem;
            }
        }
        return response;
    }

    private static final String EOL = OAuthResponseMessage.EOL;

}
