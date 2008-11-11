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

package net.oauth;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import net.oauth.http.HttpMessage;

/**
 * An OAuth message that was received via HTTP.
 * 
 * @author John Kristian
 */
public class OAuthMessageFromHttp extends OAuthMessage {

    protected OAuthMessageFromHttp(HttpMessage http) {
        super(http.method, http.url.toExternalForm(), null);
        this.http = http;
        getHeaders().addAll(http.headers);
    }

    protected final HttpMessage http;

    @Override
    public InputStream getBodyAsStream() throws IOException {
        InputStream body = super.getBodyAsStream();
        if (body != null) {
            return body;
        }
        return http.getBody();
    }

    @Override
    public String getBodyEncoding() {
        return http.getContentCharset();
    }

    @Override
    protected void dump(Map<String, Object> into) throws IOException {
        super.dump(into);
        http.dump(into);
    }

}
