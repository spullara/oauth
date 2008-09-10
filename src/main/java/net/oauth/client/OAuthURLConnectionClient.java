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
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.List;
import java.util.Map;
import net.oauth.OAuth;
import net.oauth.OAuthException;
import net.oauth.OAuthMessage;
import net.oauth.OAuthProblemException;

/**
 * Utility methods for an OAuth client based on URLConnection.
 * <p>
 * OAuthHttpClient performs better than this class, as a rule; since it does
 * things like connection pooling.
 * 
 * @author John Kristian
 */
public class OAuthURLConnectionClient extends OAuthClient {

    /** Send a message to the service provider and get the response. */
    @Override
    public OAuthMessage invoke(OAuthMessage request) throws IOException,
            OAuthException {
        final boolean sendBody = !"GET".equalsIgnoreCase(request.method);
        final URL url = new URL(sendBody ? request.URL : OAuth.addParameters(
                request.URL, request.getParameters()));
        final URLConnection connection = url.openConnection();
        if (connection instanceof HttpURLConnection) {
            HttpURLConnection http = (HttpURLConnection) connection;
            http.setRequestMethod(request.method);
            http.setInstanceFollowRedirects(false);
        }
        connection.setDoInput(true);
        if (sendBody) {
            connection.setRequestProperty("Content-Type", OAuth.FORM_ENCODED);
        }
        StringBuilder headers = new StringBuilder(request.method);
        {
            headers.append(" ").append(url.getPath());
            String query = url.getQuery();
            if (query != null && query.length() > 0) {
                headers.append("?").append(query);
            }
            headers.append("\n");
            for (Map.Entry<String, List<String>> header : connection
                    .getRequestProperties().entrySet()) {
                String key = header.getKey();
                for (String value : header.getValue()) {
                    headers.append(key).append(": ").append(value).append("\n");
                }
            }
        }
        if (sendBody) {
            String body = OAuth.formEncode(request.getParameters());
            connection.setDoOutput(true);
            OutputStream output = connection.getOutputStream();
            try {
                Writer writer = new OutputStreamWriter(output, "ISO-8859-1");
                writer.write(body);
                writer.close();
            } finally {
                output.close();
            }
        }
        final OAuthMessage response = new URLConnectionResponse(request,
                headers.toString(), connection);
        if (connection instanceof HttpURLConnection) {
            HttpURLConnection http = (HttpURLConnection) connection;
            int statusCode = http.getResponseCode();
            if (statusCode != HttpURLConnection.HTTP_OK) {
                Map<String, Object> dump = response.getDump();
                OAuthProblemException problem = new OAuthProblemException(
                        (String) dump.get(OAuthProblemException.OAUTH_PROBLEM));
                problem.getParameters().putAll(dump);
                throw problem;
            }
        }
        return response;
    }
}
