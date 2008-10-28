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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
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
 * cases. But not in all cases. For example, this class can't handle arbitrary
 * HTTP headers.
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

    /** Get a fresh request token from the service provider. */
    public void getRequestToken(OAuthAccessor accessor, String httpMethod)
            throws IOException, OAuthException, URISyntaxException {
        getRequestToken(accessor, httpMethod, null);
    }

    /** Get a fresh request token from the service provider. */
    public void getRequestToken(OAuthAccessor accessor, String httpMethod,
            Collection<? extends Map.Entry> parameters) throws IOException,
            OAuthException, URISyntaxException {
        accessor.accessToken = null;
        accessor.tokenSecret = null;
        {
            // This code supports the 'Variable Accessor Secret' extension
            // described in http://oauth.pbwiki.com/AccessorSecret
            Object accessorSecret = accessor
                    .getProperty(OAuthConsumer.ACCESSOR_SECRET);
            if (accessorSecret != null) {
                List<Map.Entry> p = (parameters == null) ? new ArrayList<Map.Entry>(
                        1)
                        : new ArrayList<Map.Entry>(parameters);
                p.add(new OAuth.Parameter("oauth_accessor_secret",
                        accessorSecret.toString()));
                parameters = p;
                // But don't modify the caller's parameters.
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

    public void getRequestToken(OAuthAccessor accessor) throws IOException,
            OAuthException, URISyntaxException {
        getRequestToken(accessor, null);
    }

    /**
     * Construct a request message, send it to the service provider and get the
     * response.
     * 
     * @return the response
     * @throws URISyntaxException
     */
    public OAuthMessage invoke(OAuthAccessor accessor, String httpMethod,
            String url, Collection<? extends Map.Entry> parameters)
            throws IOException, OAuthException, URISyntaxException {
        String ps = (String) accessor.consumer.getProperty(PARAMETER_STYLE);
        ParameterStyle style = (ps == null) ? ParameterStyle.BODY : Enum
                .valueOf(ParameterStyle.class, ps);
        return invoke(accessor.newRequestMessage(httpMethod, url, parameters),
                style);
    }

    /**
     * The name of the OAuthConsumer property whose value is the ParameterStyle
     * to be used by invoke.
     */
    public static final String PARAMETER_STYLE = "parameterStyle";

    public OAuthMessage invoke(OAuthAccessor accessor, String url,
            Collection<? extends Map.Entry> parameters) throws IOException,
            OAuthException, URISyntaxException {
        return invoke(accessor, null, url, parameters);
    }

    /** @deprecated Use invoke(OAuthMessage, ParameterStyle) instead. */
    public OAuthMessage invoke(OAuthMessage request) throws IOException,
            OAuthException {
        return invoke(request, ParameterStyle.BODY);
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
    /** Send a message to the service provider and get the response. */
    public OAuthMessage invoke(OAuthMessage request, ParameterStyle style)
            throws IOException, OAuthException {
        final boolean isPost = "POST".equalsIgnoreCase(request.method);
        final boolean isPut = "PUT".equalsIgnoreCase(request.method);
        InputStream body = request.getBodyAsStream();
        if (style == ParameterStyle.BODY && !(isPost && body == null)) {
            style = ParameterStyle.QUERY_STRING;
        }
        String url = request.URL;
        List<Map.Entry<String, String>> headers = new ArrayList<Map.Entry<String, String>>();
        String contentType = request.getContentType();
        switch (style) {
        case QUERY_STRING:
            url = OAuth.addParameters(url, request.getParameters());
            break;
        case BODY:
            body = new ByteArrayInputStream(OAuth.formEncode(
                    request.getParameters()).getBytes(
                    request.getContentCharset()));
            contentType = OAuth.FORM_ENCODED;
            break;
        case AUTHORIZATION_HEADER:
            headers.add(new OAuth.Parameter("Authorization", request
                    .getAuthorizationHeader("")));
            // Find the non-OAuth parameters:
            List<Map.Entry<String, String>> others = request.getParameters();
            if (others != null && !others.isEmpty()) {
                others = new ArrayList<Map.Entry<String, String>>(others);
                for (Iterator<Map.Entry<String, String>> p = others.iterator(); p
                        .hasNext();) {
                    if (p.next().getKey().startsWith("oauth_")) {
                        p.remove();
                    }
                }
                // Place the non-OAuth parameters elsewhere in the request:
                if (isPost && body == null) {
                    body = new ByteArrayInputStream(OAuth.formEncode(others)
                            .getBytes(request.getContentCharset()));
                } else {
                    url = OAuth.addParameters(url, others);
                }
            }
            break;
        }
        if (isPost || isPut) {
            if (contentType != null) {
                headers.add(new OAuth.Parameter("Content-Type", contentType));
            }
        }
        return invoke(request.method, url, headers, body, request
                .getContentCharset());
    }

    /** Where to place parameters in an HTTP message. */
    public enum ParameterStyle {
        AUTHORIZATION_HEADER, BODY, QUERY_STRING;
    };

    /**
     * Send an HTTP request and return the response.
     * 
     * @param method
     *                the HTTP request method; e.g. "GET" or "POST"
     * @param url
     *                identifies the HTTP server and resource
     * @param headers
     *                HTTP request headers, in addition to the standard headers.
     *                May be empty, to indicate that no additional headers are
     *                needed
     * @param body
     *                HTTP request body, or null to indicate that a body should
     *                not be transmitted
     * @return the HTTP response. Its parameters property will contain the OAuth
     *         parameters from the HTTP response, if it was successful (status
     *         200).
     */
    protected abstract OAuthMessage invoke(String method, String url,
            Collection<? extends Map.Entry<String, String>> headers,
            InputStream body, String bodyCharset) throws IOException,
            OAuthException;

    /** A decorator that retains a copy of the first few bytes of data. */
    protected static class ExcerptInputStream extends FilterInputStream {

        /**
         * A marker that's appended to the excerpt if it's less than the
         * complete stream.
         */
        public static final byte[] ELLIPSIS = " ...".getBytes();

        public ExcerptInputStream(InputStream in) {
            super(in);
        }

        private static final int maxSize = 1024;
        private final ByteArrayOutputStream excerpt = new ByteArrayOutputStream();

        /** Copy all the data from this stream to the given output stream. */
        public void copyAll(OutputStream into) throws IOException {
            byte[] b = new byte[1024];
            for (int n; 0 < (n = read(b));) {
                into.write(b, 0, n);
            }
        }

        /**
         * The first few bytes of data that have been read so far, plus ELLIPSIS
         * if this is less than all the bytes that have been read.
         */
        public byte[] getExcerpt() {
            return excerpt.toByteArray();
        }

        @Override
        public int read() throws IOException {
            byte[] b = new byte[1];
            return (read(b) <= 0) ? -1 : b[1];
        }

        @Override
        public int read(byte[] b) throws IOException {
            return read(b, 0, b.length);
        }

        @Override
        public int read(byte[] b, int offset, int length) throws IOException {
            final int n = super.read(b, offset, length);
            if (n > 0) {
                final int e = Math.min(n, maxSize - excerpt.size());
                if (e >= 0) {
                    excerpt.write(b, offset, e);
                    if (e < n) {
                        excerpt.write(ELLIPSIS);
                    }
                }
            }
            return n;
        }

    }

}
