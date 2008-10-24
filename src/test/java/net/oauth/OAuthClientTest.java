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

import java.util.List;
import java.util.Map;
import junit.framework.TestCase;
import net.oauth.client.OAuthClient;
import net.oauth.client.OAuthHttpClient;
import net.oauth.client.OAuthURLConnectionClient;

public class OAuthClientTest extends TestCase {

    public void setUp() {
        clients = new OAuthClient[] { new OAuthURLConnectionClient(), new OAuthHttpClient(),
                new net.oauth.client.httpclient4.OAuthHttpClient()};
    }

    public void testRedirect() throws Exception {
        for (OAuthClient client : clients) {
            try {
                OAuthMessage response = client.invoke(REQUEST, OAuthClient.ParameterStyle.BODY);
                fail("response: " + response);
            } catch (OAuthProblemException e) {
                Map<String, Object> parameters = e.getParameters();
                assertEquals("status", EXPECTED_STATUS, parameters
                        .get(OAuthProblemException.HTTP_STATUS_CODE));
                Map<String, String> headers = OAuth
                        .newMap(((List<OAuth.Parameter>) parameters
                                .get(OAuthProblemException.RESPONSE_HEADERS)));
                assertEquals("Location", EXPECTED_LOCATION, headers
                        .get("location"));
            }
        }
    }

    private static final OAuthMessage REQUEST = new OAuthMessage("GET",
            "http://google.com/search", OAuth.newList("q", "Java"));
    private static final Integer EXPECTED_STATUS = Integer.valueOf(301);
    private static final String EXPECTED_LOCATION = "http://www.google.com/search?q=Java";
    private OAuthClient[] clients;

}
