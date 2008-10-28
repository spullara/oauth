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
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.Socket;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import junit.framework.TestCase;
import net.oauth.client.OAuthClient;
import net.oauth.client.OAuthURLConnectionClient;
import net.oauth.client.httpclient3.OAuthHttpClient;
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
                        "GET\n" + "x=y\n", null },
                { new OAuthMessage("POST", echo, OAuth.newList("x", "y")),
                        "POST\n" + "x=y\n", OAuth.FORM_ENCODED },
                {
                        new MessageWithBody("PUT", echo, OAuth
                                .newList("x", "y"),
                                "text/plain;charset=\"UTF-8\"", "Hello!"),
                        "PUT\n" + "x=y\n" + "Hello!",
                        "text/plain; charset=UTF-8" },
                { new OAuthMessage("DELETE", echo, OAuth.newList("x", "y")),
                        "DELETE\n" + "x=y\n", null } };
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
                assertEquals(client + " " + request.method, testCase[1],
                        readAll(response.getBodyAsStream(), response
                                .getContentCharset()));
                String expectedContentType = (String) testCase[2];
                assertEquals(client + " " + request.method,
                        expectedContentType, response.getContentType());
            }
        }
    }

    private static String readAll(InputStream from, String encoding)
            throws IOException {
        StringBuilder into = new StringBuilder();
        if (from != null) {
            try {
                Reader r = new InputStreamReader(from, encoding);
                char[] s = new char[512];
                for (int n; 0 < (n = r.read(s));) {
                    into.append(s, 0, n);
                }
            } finally {
                from.close();
            }
        }
        return into.toString();
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

    private static class MessageWithBody extends OAuthMessage {

        public MessageWithBody(String method, String URL,
                Collection<? extends Entry> parameters, String contentType,
                String body) {
            super(method, URL, parameters);
            this.contentType = contentType;
            this.body = body;
        }

        private final String contentType;
        private final String body;

        @Override
        public String getBodyAsString() throws IOException {
            return body;
        }

        @Override
        public String getContentType() {
            return contentType;
        }

    }

}
