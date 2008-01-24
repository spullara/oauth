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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.oauth.signature.OAuthSignatureMethod;

/**
 * @author John Kristian
 */
public class OAuthMessage {

    public OAuthMessage(String httpMethod, String URL,
            Collection<? extends Map.Entry> parameters) {
        this.httpMethod = httpMethod;
        this.URL = URL;
        if (parameters == null) {
            this.parameters = new ArrayList<Map.Entry<String, String>>();
        } else {
            this.parameters = new ArrayList<Map.Entry<String, String>>(
                    parameters.size());
            for (Map.Entry entry : parameters) {
                this.parameters.add(new OAuth.Parameter(
                        toString(entry.getKey()), toString(entry.getValue())));
            }
        }
    }

    public final String httpMethod;

    public final String URL;

    private final List<Map.Entry<String, String>> parameters;

    private Map<String, String> parameterMap;

    public String toString() {
        return "OAuthMessage(" + httpMethod + ", " + URL + ", " + parameters
                + ")";
    }

    public List<Map.Entry<String, String>> getParameters() {
        return Collections.unmodifiableList(parameters);
    }

    public void addParameter(String key, String value) {
        addParameter(new OAuth.Parameter(key, value));
    }

    public void addParameter(Map.Entry<String, String> parameter) {
        parameters.add(parameter);
        parameterMap = null;
    }

    public void addParameters(
            Collection<? extends Map.Entry<String, String>> parameters) {
        this.parameters.addAll(parameters);
        parameterMap = null;
    }

    public String getParameter(String name) {
        return getParameterMap().get(name);
    }

    public String getConsumerKey() {
        return getParameter("oauth_consumer_key");
    }

    public String getToken() {
        return getParameter("oauth_token");
    }

    public String getSignatureMethod() {
        return getParameter("oauth_signature_method");
    }

    public String getSignature() {
        return getParameter("oauth_signature");
    }

    protected Map<String, String> getParameterMap() {
        if (parameterMap == null) {
            parameterMap = OAuth.newMap(parameters);
        }
        return parameterMap;
    }

    /** Get the body of the HTTP request or response. */
    public String getBodyAsString() throws IOException {
        return null; // stub
    }

    /** Construct a verbose description of this message and its origins. */
    public Map<String, Object> getDump() throws IOException {
        Map<String, Object> into = new HashMap<String, Object>();
        dump(into);
        return into;
    }

    protected void dump(Map<String, Object> into) throws IOException {
        into.put("URL", URL);
        try {
            into.putAll(getParameterMap());
        } catch (Exception ignored) {
        }
    }

    /**
     * Verify that the required parameter names are contained in the actual
     * collection.
     * 
     * @throws OAuthProblemException
     *             one or more parameters are absent.
     */
    public void requireParameters(String... names) throws OAuthProblemException {
        Set<String> present = getParameterMap().keySet();
        List<String> absent = new ArrayList<String>();
        for (String required : names) {
            if (!present.contains(required)) {
                absent.add(required);
            }
        }
        if (!absent.isEmpty()) {
            OAuthProblemException problem = new OAuthProblemException(
                    "parameter_absent");
            problem.setParameter("oauth_parameters_absent", OAuth
                    .percentEncode(absent));
            throw problem;
        }
    }

    /** Add a signature to the message. */
    public void sign(OAuthAccessor accessor) throws Exception {
        getSigner(accessor).sign(this);
    }

    /**
     * Check that the message has a valid signature.
     * 
     * @throws OAuthProblemException
     *             the signature is invalid
     */
    public void validateSignature(OAuthAccessor accessor) throws Exception {
        getSigner(accessor).validate(this);
    }

    private OAuthSignatureMethod getSigner(OAuthAccessor accessor)
            throws Exception {
        requireParameters("oauth_signature_method");
        OAuthSignatureMethod signer = OAuthSignatureMethod.newMethod(
                getSignatureMethod(), accessor);
        signer.setTokenSecret(accessor.tokenSecret);
        return signer;
    }

    /**
     * Construct a WWW-Authenticate or Authentication header value, containing
     * the given realm plus all the parameters whose names begin with "oauth_".
     */
    public String getAuthorizationHeader(String realm) {
        StringBuilder into = new StringBuilder(AUTH_SCHEME);
        into.append(" realm=\"").append(OAuth.percentEncode(realm)).append('"');
        if (parameters != null) {
            for (Map.Entry parameter : parameters) {
                String name = toString(parameter.getKey());
                if (name.startsWith("oauth_")) {
                    into.append(", ");
                    into.append(OAuth.percentEncode(name)).append("=\"")
                            .append(
                                    OAuth.percentEncode(toString(parameter
                                            .getValue()))).append('"');
                }
            }
        }
        return into.toString();
    }

    /**
     * Parse the parameters from an OAuth Authorization or WWW-Authenticate
     * header. The realm is included as a parameter. If the given header doesn't
     * start with "OAuth ", return an empty list.
     */
    public static List<OAuth.Parameter> decodeAuthorization(String authorization) {
        List<OAuth.Parameter> into = new ArrayList<OAuth.Parameter>();
        if (authorization != null) {
            Matcher m = AUTHORIZATION.matcher(authorization);
            if (m.matches()) {
                if (AUTH_SCHEME.equalsIgnoreCase(m.group(1))) {
                    for (String nvp : m.group(2).split("\\s*,\\s*")) {
                        m = NVP.matcher(nvp);
                        if (m.matches()) {
                            String name = OAuth.decodePercent(m.group(1));
                            String value = OAuth.decodePercent(m.group(2));
                            into.add(new OAuth.Parameter(name, value));
                        }
                    }
                }
            }
        }
        return into;
    }

    public static final String AUTH_SCHEME = "OAuth";

    static final Pattern AUTHORIZATION = Pattern.compile("\\s*(\\w*)\\s+(.*)");

    static final Pattern NVP = Pattern.compile("(\\S*)\\s*\\=\\s*\"([^\"]*)\"");

    protected static final List<Map.Entry> NO_PARAMETERS = Collections
            .emptyList();

    private static final String toString(Object from) {
        return (from == null) ? null : from.toString();
    }

}
