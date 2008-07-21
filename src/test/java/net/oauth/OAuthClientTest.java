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

package net.oauth;

import java.net.URL;
import java.util.Map;
import junit.framework.TestCase;
import net.oauth.client.HttpClientPool;
import net.oauth.client.OAuthClient;
import net.oauth.client.OAuthHttpClient;
import net.oauth.client.OAuthURLConnectionClient;
import org.apache.commons.httpclient.HttpClient;

public class OAuthClientTest extends TestCase {

    public void testRedirect() throws Exception {
        testRedirect(new OAuthHttpClient(new HttpClientPool() {
            public HttpClient getHttpClient(URL server) {
                return new HttpClient();
            }
        }));
        testRedirect(new OAuthURLConnectionClient());
    }

    private static final OAuthMessage REQUEST = new OAuthMessage("GET",
            "http://google.com/search", OAuth.newList("q", "Java"));
    private static final String EXPECTED_LOCATION = "http://www.google.com/search?q=Java";

    private void testRedirect(OAuthClient client) throws Exception {
        try {
            OAuthMessage response = client.invoke(REQUEST);
            fail("response: " + response);
        } catch (OAuthProblemException e) {
            Map<String, Object> parameters = e.getParameters();
            assertEquals("status", "301", parameters
                    .get(OAuthProblemException.HTTP_STATUS_CODE)
                    + "");
            assertEquals("Location", EXPECTED_LOCATION, parameters
                    .get(OAuthProblemException.HTTP_LOCATION)
                    + "");
        }
    }

}
