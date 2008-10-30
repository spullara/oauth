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
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import junit.framework.TestCase;
import net.oauth.OAuth;
import net.oauth.OAuthMessage;
import net.oauth.OAuthProblemException;
import net.oauth.client.OAuthClient.ExcerptInputStream;
import net.oauth.client.OAuthClient.ParameterStyle;
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
        final String data = new String(new char[] { 0, 1, ' ', 'a', 127, 128,
                0xFF, 0x3000, 0x4E00 });
        final byte[] utf8 = data.getBytes("UTF-8");
        List<OAuth.Parameter> parameters = OAuth.newList("x", "y",
                "oauth_token", "t");
        String parametersForm = "oauth_token=t&x=y";
        final Object[][] messages = new Object[][] {
                { new OAuthMessage("GET", echo, parameters),
                        "GET\n" + parametersForm + "\n", null },
                { new OAuthMessage("POST", echo, parameters),
                        "POST\n" + parametersForm + "\n", OAuth.FORM_ENCODED },
                {
                        new MessageWithBody("PUT", echo, parameters,
                                "text/OAuthClientTest; charset=\"UTF-8\"", utf8),
                        "PUT\n" + parametersForm + "\n" + data,
                        "text/OAuthClientTest; charset=UTF-8" },
                {
                        new MessageWithBody("PUT", echo, parameters,
                                "application/octet-stream", utf8),
                        "PUT\n" + parametersForm + "\n"
                                + new String(utf8, "ISO-8859-1"),
                        "application/octet-stream" },
                { new OAuthMessage("DELETE", echo, parameters),
                        "DELETE\n" + parametersForm + "\n", null } };
        final ParameterStyle[] styles = new ParameterStyle[] {
                ParameterStyle.BODY, ParameterStyle.AUTHORIZATION_HEADER };
        for (OAuthClient client : clients) {
            for (Object[] testCase : messages) {
                for (ParameterStyle style : styles) {
                    OAuthMessage request = (OAuthMessage) testCase[0];
                    final String id = client + " " + request.method + " "
                            + style;
                    OAuthMessage response = null;
                    try {
                        response = client.invoke(request, style);
                    } catch (OAuthProblemException e) {
                        fail(id + ": " + e + "\n"
                                + e.getParameters().toString());
                    }
                    // System.out.println(response.getDump()
                    // .get(OAuthMessage.HTTP_REQUEST));
                    assertEquals(id, testCase[1], OAuthMessage.readAll(response
                            .getBodyAsStream(), response.getContentCharset()));
                    assertEquals(id, testCase[2], response.getContentType());
                }
            }
        }
    }

    public void testExcerptInputStream() throws Exception {
        ExcerptInputStream input = new ExcerptInputStream(
                new ByteArrayInputStream("abcdef".getBytes()));
        assertEquals('a', input.read());
        byte[] actual = new byte[3];
        assertEquals(3, input.read(actual));
        assertEquals('b', actual[0]);
        assertEquals('c', actual[1]);
        assertEquals('d', actual[2]);
        assertEquals(1, input.read(actual, 1, 1));
        assertEquals('e', actual[1]);
        assertEquals(1, input.read(actual, 1, 2));
        assertEquals('f', actual[1]);
        assertEquals(-1, input.read());
        byte[] expected = new byte[] { -128, -1, 0, 1, 127 };
        input = new ExcerptInputStream(new ByteArrayInputStream(expected));
        actual = new byte[6];
        actual[0] = (byte) input.read();
        actual[1] = (byte) input.read();
        assertEquals(3, input.read(actual, 2, 4));
        for (int i = 0; i < expected.length; ++i) {
            assertEquals(expected[i], actual[i]);
        }
        expected = new byte[1024 + ExcerptInputStream.ELLIPSIS.length];
        for (int i = 0; i < 1024; ++i) {
            expected[i] = (byte) i;
        }
        System.arraycopy(ExcerptInputStream.ELLIPSIS, 0, expected, 1024,
                ExcerptInputStream.ELLIPSIS.length);
        input = new ExcerptInputStream(new ByteArrayInputStream(expected));
        while (input.read(actual) > 0)
            ;
        actual = input.getExcerpt();
        assertEquals(expected.length, actual.length);
        for (int i = 0; i < expected.length; ++i) {
            assertEquals(expected[i], actual[i]);
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

    private static class MessageWithBody extends OAuthMessage {

        public MessageWithBody(String method, String URL,
                Collection<OAuth.Parameter> parameters, String contentType,
                byte[] body) {
            super(method, URL, parameters);
            this.body = body;
            this.contentType = contentType;
        }

        private final byte[] body;
        private final String contentType;

        @Override
        public InputStream getBodyAsStream() throws IOException {
            return new ByteArrayInputStream(body);
        }

        public String getBodyAsString() throws IOException {
            return OAuthMessage.readAll(getBodyAsStream(), getContentCharset());
        }

        @Override
        public String getContentType() {
            return contentType;
        }

    }

}
