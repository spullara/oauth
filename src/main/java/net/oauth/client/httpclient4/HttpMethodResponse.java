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
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.util.EntityUtils;


/**
 * The response part of an HttpMethod, encapsulated as an OAuthMessage.
 * 
 * This class relies on Apache HttpClient 4.x
 * 
 *    http://hc.apache.org
 *    
 *
 */
class HttpMethodResponse extends OAuthResponseMessage {

    /**
     * Construct an OAuthMessage from the HTTP response, including parameters
     * from OAuth WWW-Authenticate headers and the body. The header parameters
     * come first, followed by the ones from the response body.
     */
    public HttpMethodResponse(HttpRequestBase request, HttpResponse response, byte[] requestBody) throws IOException {
        super(request.getMethod(), request.getURI().toString());
        this.httpRequest = request;
        this.httpResponse = response;
        this.requestBody = requestBody;
        for (Header header : response.getHeaders("WWW-Authenticate")) {
            decodeWWWAuthenticate(header.getValue());
        }
    }

    private final HttpRequestBase httpRequest;
    private final HttpResponse httpResponse;
    private final byte[] requestBody;
    private String bodyAsString = null;

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
        	if (entity == null) {
        		bodyAsString = null;
        	}
        	else {
        		bodyAsString = EntityUtils.toString(entity);
        	}
        }
        return bodyAsString;
    }

    @Override
    protected void completeParameters() throws IOException {
        Header contentType = httpResponse.getFirstHeader("Content-Type");
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
            into.put(HTTP_REQUEST_HEADERS, request.toString());
            request.append(EOL);
            if (requestBody != null) {
                request.append(new String(requestBody, "ISO-8859-1"));
            }
            into.put(HTTP_REQUEST,  request.toString());
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
