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

package net.oauth.signature;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import net.oauth.OAuthMessage;
import net.oauth.server.OAuthServlet;

/**
 * A servlet that echoes highlights of each request.
 * 
 * @author John Kristian
 */
public class Echo extends HttpServlet {

    @Override
    protected void doPut(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {
        doGet(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {
        doGet(request, response);
    }

    @Override
    protected void doDelete(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {
        doGet(request, response);
    }

    @Override
    protected void doGet(HttpServletRequest request,
            HttpServletResponse response) throws IOException {
        response.setHeader("Cache-Control", "no-cache");
        response.setContentType("application/octet-stream");
        response.setCharacterEncoding("UTF-8");
        final ServletOutputStream out = response.getOutputStream();
        out.print(request.getMethod() + "\n");
        final OAuthMessage msg = OAuthServlet.getMessage(request, null);
        out.print(OAuthSignatureMethod.normalizeParameters(msg.getParameters())
                + "\n");
        out.print(request.getContentType() + "\n");

        if ("true".equalsIgnoreCase(request.getParameter("echoHeader"))) {
            {
                String path = (new URL(request.getRequestURL().toString()))
                        .getPath();
                String queryString = request.getQueryString();
                if (queryString != null) {
                    path += ("?" + queryString);
                }
                out.println(request.getMethod() + " " + path);
            }
            for (Enumeration names = request.getHeaderNames(); names
                    .hasMoreElements();) {
                final String name = names.nextElement().toString();
                for (Enumeration values = request.getHeaders(name); values
                        .hasMoreElements();) {
                    final Object value = values.nextElement();
                    out.println(name + ": " + value);
                }
            }
            out.println();
        }
        if ("true".equalsIgnoreCase(request.getParameter("echoParameters"))) {
            final Map parameters = request.getParameterMap();
            for (Object name : parameters.keySet()) {
                for (String value : (String[]) parameters.get(name)) {
                    out.println(name + ": " + value);
                }
            }
            out.println();
        }
        final String echoData = request.getParameter("echoData");
        if (echoData != null) {
            int n = Integer.parseInt(echoData);
            for (; n > 0; n -= (DATA.length + 1)) {
                int len = Math.min(n - 1, DATA.length);
                out.write(DATA, 0, len);
                out.write('\n');
            }
            out.write('\n');
        }
        if (!"false".equalsIgnoreCase(request.getParameter("echoBody"))) {
            ServletInputStream in = request.getInputStream();
            final byte[] buffer = new byte[1024];
            int n;
            while (0 < (n = in.read(buffer))) {
                out.write(buffer, 0, n);
            }
        }
    }

    private static final byte[] DATA = getData();

    private static byte[] getData() {
        try {
            return "abcdefghi1abcdefghi2abcdefghi3abcdefghi4abcdefghi"
                    .getBytes("UTF-8");
        } catch (UnsupportedEncodingException wow) {
            wow.printStackTrace();
        }
        final byte[] data = new byte[49];
        Arrays.fill(data, (byte) 'x');
        return data;
    }

    private static final long serialVersionUID = 1L;

}
