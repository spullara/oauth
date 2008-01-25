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

package net.oauth.signature;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import net.oauth.OAuth;
import net.oauth.OAuthAccessor;
import net.oauth.OAuthConsumer;
import net.oauth.OAuthMessage;
import net.oauth.OAuthProblemException;
import org.apache.commons.codec.binary.Base64;

/**
 * A pair of algorithms for computing and verifying an OAuth digital signature.
 * 
 * @author John Kristian
 */
public abstract class OAuthSignatureMethod {

    /** Add a signature to the message. */
    public void sign(OAuthMessage message) throws Exception {
        message.addParameter(new OAuth.Parameter("oauth_signature",
                getSignature(message)));
    }

    /**
     * Check whether the message has a valid signature.
     * 
     * @throws OAuthProblemException
     *             the signature is invalid
     */
    public void validate(OAuthMessage message) throws Exception {
        message.requireParameters("oauth_signature");
        String signature = message.getSignature();
        String baseString = getBaseString(message);
        if (!isValid(signature, baseString)) {
            OAuthProblemException problem = new OAuthProblemException(
                    "signature_invalid");
            problem.setParameter("oauth_signature", signature);
            problem.setParameter("oauth_signature_base_string", baseString);
            problem.setParameter("oauth_signature_method", message
                    .getSignatureMethod());
            throw problem;
        }
    }

    protected String getSignature(OAuthMessage message) throws Exception {
        String baseString = getBaseString(message);
        String signature = getSignature(baseString);
        // Logger log = Logger.getLogger(getClass().getName());
        // if (log.isLoggable(Level.FINE)) {
        // log.fine(signature + "=getSignature(" + baseString + ")");
        // }
        return signature;
    }

    protected void initialize(String name, OAuthAccessor accessor)
            throws Exception {
        String secret = accessor.consumer.consumerSecret;
        if (name.endsWith(_ACCESSOR)) {
            // This code supports the 'Accessor Secret' extensions
            // described in http://oauth.pbwiki.com/AccessorSecret
            final String key = OAuthConsumer.ACCESSOR_SECRET;
            Object accessorSecret = accessor.getProperty(key);
            if (accessorSecret == null) {
                accessorSecret = accessor.consumer.getProperty(key);
            }
            if (accessorSecret != null) {
                secret = accessorSecret.toString();
            }
        }
        if (secret == null) {
            secret = "";
        }
        setConsumerSecret(secret);
    }

    public static final String _ACCESSOR = "-Accessor";

    /** Compute the signature for the given base string. */
    protected abstract String getSignature(String baseString) throws Exception;

    /** Decide whether the signature is valid. */
    protected abstract boolean isValid(String signature, String baseString)
            throws Exception;

    private String consumerSecret;

    private String tokenSecret;

    protected String getConsumerSecret() {
        return consumerSecret;
    }

    protected void setConsumerSecret(String consumerSecret) {
        this.consumerSecret = consumerSecret;
    }

    public String getTokenSecret() {
        return tokenSecret;
    }

    public void setTokenSecret(String tokenSecret) {
        this.tokenSecret = tokenSecret;
    }

    protected static String getBaseString(OAuthMessage message)
            throws IOException {
        List<Map.Entry<String, String>> parameters;
        String url = message.URL;
        int q = url.indexOf('?');
        if (q < 0) {
            parameters = message.getParameters();
        } else {
            // Combine the URL query string with the other parameters:
            parameters = new ArrayList<Map.Entry<String, String>>();
            parameters.addAll(OAuth.decodeForm(message.URL.substring(q + 1)));
            parameters.addAll(message.getParameters());
            url = url.substring(0, q);
        }
        return OAuth.percentEncode(message.method.toUpperCase()) + '&'
                + OAuth.percentEncode(url) + '&'
                + OAuth.percentEncode(normalizeParameters(parameters));
    }

    protected static String normalizeParameters(
            Collection<? extends Map.Entry> parameters) throws IOException {
        if (parameters == null) {
            return "";
        }
        List<ComparableParameter> p = new ArrayList<ComparableParameter>(
                parameters.size());
        for (Map.Entry parameter : parameters) {
            if (!"oauth_signature".equals(parameter.getKey())) {
                p.add(new ComparableParameter(parameter));
            }
        }
        Collections.sort(p);
        return OAuth.formEncode(getParameters(p));
    }

    public static byte[] decodeBase64(String s) {
        return BASE64.decode(s.getBytes());
    }

    public static String base64Encode(byte[] b) {
        return new String(BASE64.encode(b));
    }

    private static final Base64 BASE64 = new Base64();

    /** The factory for signature methods. */
    public static OAuthSignatureMethod newMethod(String name,
            OAuthAccessor accessor) throws Exception {
        Class methodClass = NAME_TO_CLASS.get(name);
        if (methodClass != null) {
            OAuthSignatureMethod method = (OAuthSignatureMethod) methodClass
                    .newInstance();
            method.initialize(name, accessor);
            return method;
        }
        OAuthProblemException problem = new OAuthProblemException(
                "signature_method_rejected");
        String acceptable = OAuth.percentEncode(NAME_TO_CLASS.keySet());
        if (acceptable.length() > 0) {
            problem.setParameter("oauth_acceptable_signature_methods",
                    acceptable.toString());
        }
        throw problem;
    }

    /**
     * Subsequently, newMethod(name) will attempt to instantiate the given
     * class, with no constructor parameters.
     */
    public static void registerMethodClass(String name, Class clazz) {
        NAME_TO_CLASS.put(name, clazz);
    }

    private static final Map<String, Class> NAME_TO_CLASS = new ConcurrentHashMap<String, Class>();
    static {
        registerMethodClass("HMAC-SHA1", HMAC_SHA1.class);
        registerMethodClass("PLAINTEXT", PLAINTEXT.class);
        registerMethodClass("RSA-SHA1", RSA_SHA1.class);
        registerMethodClass("HMAC-SHA1" + _ACCESSOR, HMAC_SHA1.class);
        registerMethodClass("PLAINTEXT" + _ACCESSOR, PLAINTEXT.class);
    }

    /** An efficiently sortable wrapper around a parameter. */
    private static class ComparableParameter implements
            Comparable<ComparableParameter> {

        ComparableParameter(Map.Entry value) {
            this.value = value;
            String n = toString(value.getKey());
            String v = toString(value.getValue());
            this.key = OAuth.percentEncode(n) + ' ' + OAuth.percentEncode(v);
            // ' ' is used because it comes before any character
            // that can appear in a percentEncoded string.
        }

        final Map.Entry value;

        private final String key;

        private static String toString(Object from) {
            return (from == null) ? null : from.toString();
        }

        public int compareTo(ComparableParameter that) {
            return this.key.compareTo(that.key);
        }

        @Override
        public String toString() {
            return key;
        }

    }

    /** Retrieve the original parameters from a sorted collection. */
    private static List<Map.Entry> getParameters(
            Collection<ComparableParameter> parameters) {
        if (parameters == null) {
            return null;
        }
        List<Map.Entry> list = new ArrayList<Map.Entry>(parameters.size());
        for (ComparableParameter parameter : parameters) {
            list.add(parameter.value);
        }
        return list;
    }

}
