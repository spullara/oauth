package net.oauth.client;

import static junit.framework.Assert.assertEquals;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import net.oauth.OAuth;
import net.oauth.OAuthMessage;
import net.oauth.OAuthProblemException;
import net.oauth.client.OAuthClient.ParameterStyle;
import net.oauth.client.httpclient4.HttpClient4;
import net.oauth.http.HttpMessage;

public class Upload {
    public static void main(String[] args) throws IOException, OAuthProblemException {
        final String echo = "http://oauth-sandbox.mediamatic.nl/module/OAuth/request_token";
        final Class myClass = Upload.class;
        final String sourceName = "/" + myClass.getPackage().getName().replace('.', '/') + "/flower.jpg";
        final URL source = myClass.getResource(sourceName);
        OAuthClient client = new OAuthClient(new HttpClient4());
        ParameterStyle style = ParameterStyle.QUERY_STRING;
        final String id = client + " POST " + style;
        OAuthMessage response = null;
        InputStream input = source.openStream();
        try {
            OAuthMessage request = new OAuthClientTest.InputStreamMessage(OAuthMessage.PUT, echo, input);
            request.addParameter(new OAuth.Parameter("oauth_token", "t"));
            request.getHeaders().add(new OAuth.Parameter("Content-Type", "image/jpeg"));
            response = client.invoke(request, style);
        } catch (OAuthProblemException e) {
            // System.err.println(e.getParameters().get(HttpMessage.REQUEST));
            System.err.println(e.getParameters().get(HttpMessage.RESPONSE));
            throw e;
        } catch (Exception e) {
            AssertionError failure = new AssertionError();
            failure.initCause(e);
            throw failure;
        } finally {
            input.close();
        }
        assertEquals(id, "image/jpeg", response.getHeader("Content-Type"));
        byte[] data = OAuthClientTest.readAll(source.openStream());
        Integer contentLength = (client.getHttpClient() instanceof HttpClient4) ? null : new Integer(data.length);
        byte[] expected = OAuthClientTest.concatenate((OAuthMessage.PUT + "\noauth_token=t\n" + contentLength + "\n").getBytes(), data);
        byte[] actual = OAuthClientTest.readAll(response.getBodyAsStream());
        StreamTest.assertEqual(id, expected, actual);
    }
}
