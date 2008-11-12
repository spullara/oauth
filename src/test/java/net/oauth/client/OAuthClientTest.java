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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.Socket;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import junit.framework.TestCase;
import net.oauth.OAuth;
import net.oauth.OAuthMessage;
import net.oauth.OAuthProblemException;
import net.oauth.client.OAuthClient.ParameterStyle;
import net.oauth.http.HttpMessage;
import net.oauth.http.HttpMessageDecoder;
import net.oauth.http.HttpResponseMessage;
import net.oauth.signature.Echo;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.servlet.Context;
import org.mortbay.jetty.servlet.ServletHolder;
import org.mortbay.servlet.GzipFilter;
import org.mortbay.thread.BoundedThreadPool;

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
                assertEquals("status", expectedStatus, parameters.get(HttpResponseMessage.STATUS_CODE));
                assertEquals("Location", expectedLocation, parameters.get(HttpResponseMessage.LOCATION));
            }
        }
    }

    public void testInvokeMessage() throws Exception {
        final String echo = "http://localhost:" + port + "/Echo";
        final String data = new String(new char[] { 0, 1, ' ', 'a', 127, 128,
                0xFF, 0x3000, 0x4E00 });
        final byte[] utf8 = data.getBytes("UTF-8");
        List<OAuth.Parameter> parameters = OAuth.newList("x", "y",
                "oauth_token", "t");
        String parametersForm = "oauth_token=t&x=y";
        final Object[][] messages = new Object[][] {
                { new OAuthMessage("GET", echo, parameters),
                        "GET\n" + parametersForm + "\n" + "null\n", null },
                {
                        new OAuthMessage("POST", echo, parameters),
                        "POST\n" + parametersForm + "\n"
                                + parametersForm.length() + "\n",
                        OAuth.FORM_ENCODED },
                {
                        new MessageWithBody("PUT", echo, parameters,
                                "text/OAuthClientTest; charset=\"UTF-8\"", utf8),
                        "PUT\n" + parametersForm + "\n"
                                + utf8.length + "\n" + data,
                        "text/OAuthClientTest; charset=UTF-8" },
                {
                        new MessageWithBody("PUT", echo, parameters,
                                "application/octet-stream", utf8),
                        "PUT\n" + parametersForm + "\n"
                                + utf8.length + "\n"
                                + new String(utf8, "ISO-8859-1"),
                        "application/octet-stream" },
                { new OAuthMessage("DELETE", echo, parameters),
                        "DELETE\n" + parametersForm + "\n" + "null\n", null } };
        final ParameterStyle[] styles = new ParameterStyle[] {
                ParameterStyle.BODY, ParameterStyle.AUTHORIZATION_HEADER };
        for (OAuthClient client : clients) {
            for (Object[] testCase : messages) {
                for (ParameterStyle style : styles) {
                    OAuthMessage request = (OAuthMessage) testCase[0];
                    final String id = client + " " + request.method + " " + style;
                    OAuthMessage response = null;
                    // System.out.println(id + " ...");
                    try {
                        response = client.invoke(request, style);
                    } catch (Exception e) {
                        AssertionError failure = new AssertionError(id);
                        failure.initCause(e);
                        throw failure;
                    }
                    // System.out.println(response.getDump()
                    // .get(OAuthMessage.HTTP_REQUEST));
                    String expectedBody = (String) testCase[1];
                    if ("POST".equalsIgnoreCase(request.method)
                            && style == ParameterStyle.AUTHORIZATION_HEADER) {
                        // Only the non-oauth parameters went in the body.
                        expectedBody = expectedBody.replace("\n" + parametersForm.length()
                                + "\n", "\n3\n");
                    }
                    String body = response.readBodyAsString();
                    assertEquals(id, expectedBody, body);
                    assertEquals(id, testCase[2], response.getHeader(HttpMessage.CONTENT_TYPE));
                }
            }
        }
    }

    public void testGzip() throws Exception {
        final MessageWithBody request = new MessageWithBody("POST",
                "http://localhost:" + port + "/Echo",
                OAuth.newList("echoData", "21"), null, null);
        final String expected = "POST\nechoData=21\nabcdefghi1abcdefghi2\n\n11\n";
        for (OAuthClient client : clients) {
            try {
                OAuthMessage response = client.invoke(request, ParameterStyle.AUTHORIZATION_HEADER);
                System.out.println(response.getDump().get(HttpMessage.REQUEST));
                System.out.println(response.getDump().get(HttpMessage.RESPONSE));
                assertEquals(client.getClass().getName(), expected, response.readBodyAsString());
                // assertEqual(client.getClass().getName(), OAuth.decodeForm(expected), response.getParameters());
            } catch (OAuthProblemException e) {
                Map<String, Object> p = e.getParameters();
                System.out.println(p.get(HttpMessage.REQUEST));
                System.err.println(p.get(HttpMessage.RESPONSE));
                throw e;
            } catch(Exception e) {
                AssertionError a = new AssertionError(client.getClass().getName());
                a.initCause(e);
                throw a;
            }
            System.out.println();
        }
    }

    private OAuthClient[] clients;
    private int port = 1025;
    private Server server;

    @Override
    public void setUp() throws Exception {
        clients = new OAuthClient[] { new OAuthURLConnectionClient(),
                new net.oauth.client.httpclient3.OAuthHttpClient(),
                new net.oauth.client.httpclient4.OAuthHttpClient() };
        { // Get an ephemeral local port number:
            Socket s = new Socket();
            s.bind(null);
            port = s.getLocalPort();
            s.close();
        }
        server = new Server(port);
        Context context = new Context(server, "/", Context.SESSIONS);
        context.addFilter(GzipFilter.class, "/*", 1);
        context.addServlet(new ServletHolder(new Echo()), "/Echo/*");
        BoundedThreadPool pool = new BoundedThreadPool();
        pool.setMaxThreads(4);
        server.setThreadPool(pool);
        server.start();
    }

    @Override
    public void tearDown() throws Exception {
        server.stop();
    }

    private static class MessageWithBody extends OAuthMessage {

        public MessageWithBody(String method, String URL,
                Collection<OAuth.Parameter> parameters,
                String contentType, byte[] body) {
            super(method, URL, parameters);
            this.body = body;
            Collection<Map.Entry<String, String>> headers = getHeaders();
            headers.add(new OAuth.Parameter(HttpMessage.ACCEPT_ENCODING, HttpMessageDecoder.ACCEPTED));
            if (body != null) {
                headers.add(new OAuth.Parameter(HttpMessage.CONTENT_LENGTH, String.valueOf(body.length)));
            }
            if (contentType != null) {
                headers.add(new OAuth.Parameter(HttpMessage.CONTENT_TYPE, contentType));
            }
        }

        private final byte[] body;

        @Override
        public InputStream getBodyAsStream() {
            return (body == null) ? null : new ByteArrayInputStream(body);
        }
    }

}
