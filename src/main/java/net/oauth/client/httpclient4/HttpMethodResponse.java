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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.oauth.OAuth;
import net.oauth.OAuthProblemException;
import net.oauth.client.OAuthResponseMessage;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.util.EntityUtils;

/**
 * An HttpResponse, encapsulated as an OAuthMessage.
 * 
 * This class relies on <a href="http://hc.apache.org">Apache HttpClient</a>
 * version 4.
 * 
 * @author Sean Sullivan
 */
public class HttpMethodResponse extends OAuthResponseMessage {

    /**
     * Construct an OAuthMessage from the HTTP response, including parameters
     * from OAuth WWW-Authenticate headers and the body. The header parameters
     * come first, followed by the ones from the response body.
     */
    public HttpMethodResponse(HttpRequestBase request, HttpResponse response,
            byte[] requestBody, String requestEncoding) throws IOException
    {
        super(request.getMethod(), request.getURI().toString());
        this.httpRequest = request;
        this.httpResponse = response;
        this.requestBody = requestBody;
        this.requestEncoding = requestEncoding;
        for (Header header : response.getHeaders("WWW-Authenticate")) {
            decodeWWWAuthenticate(header.getValue());
        }
        Header[] headers = response.getHeaders(CONTENT_TYPE);
        contentType = (headers == null || headers.length <= 0) ? null
                : headers[headers.length - 1].getValue();
    }

    private final HttpRequestBase httpRequest;
    private final HttpResponse httpResponse;
    private final byte[] requestBody;
    private final String requestEncoding;
    private String bodyAsString = null;
    private final String contentType;

    @Override
    public String getContentType() {
        return contentType;
    }

    @Override
    public String getHeader(String name) {
        Header[] headers = httpResponse.getHeaders(name);
        if (headers != null && headers.length > 0) {
            return headers[headers.length - 1].getValue();
        }
        return null; // no such header
    }

    @Override
    public List<Map.Entry<String, String>> getHeaders() {
        List<Map.Entry<String, String>> headers = new ArrayList<Map.Entry<String, String>>();
        Header[] allHeaders = httpResponse.getAllHeaders();
        if (allHeaders != null) {
            for (Header header : allHeaders) {
                headers.add(new OAuth.Parameter(header.getName(), header
                        .getValue()));
            }
        }
        return headers;
    }

    @Override
    public InputStream getBodyAsStream() throws IOException {
        if (bodyAsString == null) {
            return httpResponse.getEntity().getContent();
        }
        return super.getBodyAsStream();
    }

    @Override
    public String getBodyAsString() throws IOException {
        if (bodyAsString == null) {
            HttpEntity entity = httpResponse.getEntity();
            if (entity != null) {
                bodyAsString = EntityUtils.toString(entity);
            }
        }
        return bodyAsString;
    }

    @Override
    protected void completeParameters() throws IOException {
        Header contentType = httpResponse.getLastHeader(CONTENT_TYPE);
        if (contentType == null || isDecodable(contentType.getValue())) {
            super.completeParameters();
        }
    }

    /** Return a complete description of the HTTP exchange. */
    @Override
    protected void dump(Map<String, Object> into) throws IOException {
        super.dump(into);
        {
            StringBuilder request = new StringBuilder(httpRequest.getMethod());
            request.append(" ").append(httpRequest.getURI().getPath());
            String query = httpRequest.getURI().getQuery();
            if (query != null && query.length() > 0) {
                request.append("?").append(query);
            }
            request.append(EOL);
            for (Header header : httpRequest.getAllHeaders()) {
                request.append(header.getName()).append(": ").append(
                        header.getValue()).append(EOL);
            }
            if (httpRequest instanceof HttpEntityEnclosingRequest) {
                HttpEntityEnclosingRequest r = (HttpEntityEnclosingRequest) httpRequest;
                long contentLength = r.getEntity().getContentLength();
                if (contentLength >= 0) {
                    request.append("Content-Length: ").append(contentLength).append(EOL);
                }
            }
            into.put(HTTP_REQUEST_HEADERS, request.toString());
            request.append(EOL);
            if (requestBody != null) {
                request.append(new String(requestBody, requestEncoding));
            }
            into.put(HTTP_REQUEST, request.toString());
        }
        into.put(OAuthProblemException.HTTP_STATUS_CODE, //
                new Integer(httpResponse.getStatusLine().getStatusCode()));
        {
            List<OAuth.Parameter> responseHeaders = new ArrayList<OAuth.Parameter>();
            StringBuilder response = new StringBuilder();
            String value = httpResponse.getStatusLine().toString();
            response.append(value).append(EOL);
            responseHeaders.add(new OAuth.Parameter(null, value));
            for (Header header : httpResponse.getAllHeaders()) {
                String name = header.getName();
                value = header.getValue();
                response.append(name).append(": ").append(value).append(EOL);
                responseHeaders.add(new OAuth.Parameter(name.toLowerCase(),
                        value));
            }
            into.put(OAuthProblemException.RESPONSE_HEADERS, responseHeaders);
            response.append(EOL);
            String body = getBodyAsString();
            if (body != null) {
                response.append(body);
            }
            into.put(HTTP_RESPONSE, response.toString());
        }
    }

}
