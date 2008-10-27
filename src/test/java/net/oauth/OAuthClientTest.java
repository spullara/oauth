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

import java.net.Socket;
import java.util.List;
import java.util.Map;
import junit.framework.TestCase;
import net.oauth.client.OAuthClient;
import net.oauth.client.OAuthHttpClient;
import net.oauth.client.OAuthURLConnectionClient;
import net.oauth.signature.Echo;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.servlet.Context;
import org.mortbay.jetty.servlet.ServletHolder;

public class OAuthClientTest extends TestCase {

    public void testRedirect() throws Exception {
        final OAuthMessage request = new OAuthMessage("GET",
                "http://google.com/search", OAuth.newList("q", "Java"));
        final Integer expectedStatus = Integer.valueOf(301);
        final String expectedLocation = "http://www.google.com/search?q=Java";
        for (OAuthClient client : clients) {
            try {
                OAuthMessage response = client.invoke(request,
                        OAuthClient.ParameterStyle.BODY);
                fail("response: " + response);
            } catch (OAuthProblemException e) {
                Map<String, Object> parameters = e.getParameters();
                assertEquals("status", expectedStatus, parameters
                        .get(OAuthProblemException.HTTP_STATUS_CODE));
                Map<String, String> headers = OAuth
                        .newMap(((List<OAuth.Parameter>) parameters
                                .get(OAuthProblemException.RESPONSE_HEADERS)));
                assertEquals("Location", expectedLocation, headers
                        .get("location"));
            }
        }
    }

    public void testInvokeMessage() throws Exception {
        final String echo = "http://localhost:" + port + "/Echo";
        final Object[][] messages = new Object[][] {
                { new OAuthMessage("GET", echo, OAuth.newList("x", "y")),
                        "GET\n" + "x=y\n" + null + "\n" },
                { new OAuthMessage("POST", echo, OAuth.newList("x", "y")),
                        "POST\n" + "x=y\n" + OAuth.FORM_ENCODED + "\n" },
                { new OAuthMessage("PUT", echo, OAuth.newList("x", "y")),
                        "PUT\n" + "x=y\n" + null + "\n" } };
        for (OAuthClient client : clients) {
            for (Object[] testCase : messages) {
                OAuthMessage request = (OAuthMessage) testCase[0];
                OAuthMessage response = null;
                try {
                    response = client.invoke(request,
                            OAuthClient.ParameterStyle.BODY);
                } catch (OAuthProblemException e) {
                    fail(e.getParameters().toString());
                }
                assertEquals(client.toString(), testCase[1], response
                        .getBodyAsString());
            }
        }
    }
    private OAuthClient[] clients;
    private int port = 1025;
    private Server server;

    @Override
    public void setUp() throws Exception {
        clients = new OAuthClient[] { new OAuthHttpClient(),
                new OAuthURLConnectionClient(),
                new net.oauth.client.httpclient4.OAuthHttpClient() };
        { // Get an ephemeral local port number:
            Socket s = new Socket();
            s.bind(null);
            port = s.getLocalPort();
            s.close();
        }
        server = new Server(port);
        Context context = new Context(server, "/", Context.SESSIONS);
        context.addServlet(new ServletHolder(new Echo()), "/Echo/*");
        server.start();
    }

    @Override
    public void tearDown() throws Exception {
        server.stop();
    }

}
