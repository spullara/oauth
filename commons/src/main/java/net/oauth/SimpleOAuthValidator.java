/*
 * Copyright 2008 Google, Inc.
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
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import net.oauth.signature.OAuthSignatureMethod;

/**
 * A simple OAuthValidator, which checks the version, whether the timestamp is
 * close to now, the nonce hasn't been used before and the signature is valid.
 * Each check may be overridden.
 * <p>
 * This implementation is less than industrial strength. The range of acceptable
 * timestamps can't be changed, and there's no system for increasing the range
 * smoothly. Duplicate nonces won't be reliably detected by a service provider
 * running in multiple processes, unless their validator objects are mirrored or
 * requests are consistently routed to the same process based on their
 * timestamp, nonce or consumer key. The collection of used nonces is a
 * synchronized choke point, and may occupy lots of memory. You can mitigate the
 * memory consumption by calling releaseGarbage periodically. For a big service
 * provider, it might be better to store used nonces in a database.
 * 
 * @author Dirk Balfanz
 * @author John Kristian
 */
public class SimpleOAuthValidator implements OAuthValidator {

    /** The default window for timestamps is 5 minutes. */
    public static final long DEFAULT_TIMESTAMP_WINDOW = 5 * 60 * 1000L;

    /**
     * Names of parameters that may not appear twice in a valid message.
     * This limitation is specified by OAuth Core <a
     * href="http://oauth.net/core/1.0#anchor7">section 5</a>.
     */
    public static final Set<String> SINGLE_PARAMETERS = constructSingleParameters();

    private static Set<String> constructSingleParameters() {
        Set<String> s = new HashSet<String>();
        for (String p : new String[] { OAuth.OAUTH_CONSUMER_KEY, OAuth.OAUTH_TOKEN, OAuth.OAUTH_TOKEN_SECRET,
                OAuth.OAUTH_CALLBACK, OAuth.OAUTH_SIGNATURE_METHOD, OAuth.OAUTH_SIGNATURE, OAuth.OAUTH_TIMESTAMP,
                OAuth.OAUTH_NONCE, OAuth.OAUTH_VERSION }) {
            s.add(p);
        }
        return Collections.unmodifiableSet(s);
    }

    /**
     * Construct a validator that rejects messages more than five minutes out
     * of date, or with a OAuth version other than 1.0, or with an invalid
     * signature.
     */
    public SimpleOAuthValidator() {
        this(DEFAULT_TIMESTAMP_WINDOW, Double.parseDouble(OAuth.VERSION_1_0));
    }

    /**
     * Public constructor.
     *
     * @param timestampWindowSec
     *            specifies, in seconds, the windows (into the past and
     *            into the future) in which we'll accept timestamps.
     * @param maxVersion
     *            the maximum acceptable oauth_version
     */
    public SimpleOAuthValidator(long timestampWindowMsec, double maxVersion) {
        this.timestampWindowMsec = timestampWindowMsec;
        this.maxVersion = maxVersion;
    }

    protected final double minVersion = 1.0;
    protected final double maxVersion;
    protected final long timestampWindowMsec;
    protected final Set<UsedNonce> usedNonces = new TreeSet<UsedNonce>();

    /** Allow objects that are no longer useful to become garbage. */
    public void releaseGarbage() {
        releaseUsedNonces((currentTimeMsec() - timestampWindowMsec) / 1000L);
    }

    /** Remove usedNonces older than the given time. */
    private void releaseUsedNonces(long minimumTime) {
        UsedNonce limit = new UsedNonce(minimumTime);
        synchronized (usedNonces) {
            // Because usedNonces is a TreeSet, its iterator produces
            // elements from oldest to newest (their natural order).
            for (Iterator<UsedNonce> iter = usedNonces.iterator(); iter.hasNext();) {
                UsedNonce t = iter.next();
                if (limit.compareTo(t) <= 0)
                    break; // all the rest are new enough
                iter.remove(); // too old
            }
        }
    }

    /** {@inherit} 
     * @throws URISyntaxException */
    public void validateMessage(OAuthMessage message, OAuthAccessor accessor)
    throws OAuthException, IOException, URISyntaxException {
        checkSingleParameters(message);
        validateVersion(message);
        validateTimestampAndNonce(message);
        validateSignature(message, accessor);
    }

    /** Throw an exception if any SINGLE_PARAMETERS occur repeatedly. */
    protected void checkSingleParameters(OAuthMessage message) throws IOException, OAuthException {
        // Check for repeated oauth_ parameters:
        boolean repeated = false;
        Map<String, Collection<String>> nameToValues = new HashMap<String, Collection<String>>();
        for (Map.Entry<String, String> parameter : message.getParameters()) {
            String name = parameter.getKey();
            if (SINGLE_PARAMETERS.contains(name)) {
                Collection<String> values = nameToValues.get(name);
                if (values == null) {
                    values = new ArrayList<String>();
                    nameToValues.put(name, values);
                } else {
                    repeated = true;
                }
                values.add(parameter.getValue());
            }
        }
        if (repeated) {
            Collection<OAuth.Parameter> rejected = new ArrayList<OAuth.Parameter>();
            for (Map.Entry<String, Collection<String>> p : nameToValues.entrySet()) {
                String name = p.getKey();
                Collection<String> values = p.getValue();
                if (values.size() > 1) {
                    for (String value : values) {
                        rejected.add(new OAuth.Parameter(name, value));
                    }
                }
            }
            OAuthProblemException problem = new OAuthProblemException(OAuth.Problems.PARAMETER_REJECTED);
            problem.setParameter(OAuth.Problems.OAUTH_PARAMETERS_REJECTED, OAuth.formEncode(rejected));
            throw problem;
        }
    }

    protected void validateVersion(OAuthMessage message)
    throws OAuthException, IOException {
        String versionString = message.getParameter(OAuth.OAUTH_VERSION);
        if (versionString != null) {
            double version = Double.parseDouble(versionString);
            if (version < minVersion || maxVersion < version) {
                OAuthProblemException problem = new OAuthProblemException(OAuth.Problems.VERSION_REJECTED);
                problem.setParameter(OAuth.Problems.OAUTH_ACCEPTABLE_VERSIONS, minVersion + "-" + maxVersion);
                throw problem;
            }
        }
    }

    /**
     * Throw an exception if the timestamp is out of range or the nonce has been
     * validated previously.
     */
    protected void validateTimestampAndNonce(OAuthMessage message)
    throws IOException, OAuthProblemException {
        message.requireParameters(OAuth.OAUTH_TIMESTAMP, OAuth.OAUTH_NONCE);
        long timestamp = Long.parseLong(message.getParameter(OAuth.OAUTH_TIMESTAMP));
        long min = validateTimestamp(message, timestamp);
        validateNonce(message, timestamp, min);
    }

    /**
     * Throw an exception if the timestamp [sec] is out of range.
     * @return the minimum acceptable timestamp [sec]
     */
    protected long validateTimestamp(OAuthMessage message, long timestamp)
    throws IOException, OAuthProblemException {
        long now = currentTimeMsec();
        long min = (now - timestampWindowMsec + 500) / 1000L;
        long max = (now + timestampWindowMsec + 500) / 1000L;
        if (timestamp < min || max < timestamp) {
            OAuthProblemException problem = new OAuthProblemException(OAuth.Problems.TIMESTAMP_REFUSED);
            problem.setParameter(OAuth.Problems.OAUTH_ACCEPTABLE_TIMESTAMPS, min + "-" + max);
            throw problem;
        }
        return min;
    }

    /**
     * Throw an exception if the nonce has been validated previously.
     */
    protected void validateNonce(OAuthMessage message, long timestamp, long min)
    throws IOException, OAuthProblemException {
        UsedNonce nonce = new UsedNonce(timestamp,
                message.getParameter(OAuth.OAUTH_NONCE), message.getConsumerKey(), message.getToken());
        // The OAuth standard requires the token to be omitted from the stored nonce.
        // But I imagine a Consumer might be unable to coordinate the coining of
        // nonces by clients on many computers, each with its own token.
        synchronized (usedNonces) {
            if (!usedNonces.add(nonce)) {
                // It was already in the set.
                throw new OAuthProblemException(OAuth.Problems.NONCE_USED);
            }
        }
        releaseUsedNonces(min);
    }

    protected void validateSignature(OAuthMessage message, OAuthAccessor accessor)
    throws OAuthException, IOException, URISyntaxException {
        message.requireParameters(OAuth.OAUTH_CONSUMER_KEY,
                OAuth.OAUTH_SIGNATURE_METHOD, OAuth.OAUTH_SIGNATURE);
        OAuthSignatureMethod.newSigner(message, accessor).validate(message);
    }

    protected long currentTimeMsec() {
        return System.currentTimeMillis();
    }

    /**
     * Selected parameters from an OAuth request, in a form suitable for
     * detecting duplicate requests. The implementation is optimized for the
     * comparison operations (compareTo, equals and hashCode).
     * 
     * @author John Kristian
     */
    private static class UsedNonce implements Comparable<UsedNonce> {
        /**
         * Construct an object containing the given timestamp, nonce and other
         * parameters. The order of parameters is significant.
         */
        UsedNonce(long timestamp, String... nonceEtc) {
            StringBuilder key = new StringBuilder(String.format("%20d", Long.valueOf(timestamp)));
            // The blank padding ensures that timestamps are compared as numbers.
            for (String etc : nonceEtc) {
                key.append("&").append(etc == null ? " " : OAuth.percentEncode(etc));
                // A null value is different from "" or any other String.
            }
            sortKey = key.toString();
        }

        private final String sortKey;

        /**
         * Determine the relative order of <code>this</code> and
         * <code>that</code>, as specified by Comparable. The timestamp is most
         * significant; that is, if the timestamps are different, return 1 or
         * -1. If <code>this</code> contains only a timestamp (with no nonce
         * etc.), return -1 or 0. The treatment of the nonce etc. is murky,
         * although 0 is returned only if they're all equal.
         */
        public int compareTo(UsedNonce that) {
            return (that == null) ? 1 : sortKey.compareTo(that.sortKey);
        }

        @Override
        public int hashCode() {
            return sortKey.hashCode();
        }

        /**
         * Return true iff <code>this</code> and <code>that</code> contain equal
         * timestamps, nonce etc., in the same order.
         */
        @Override
        public boolean equals(Object that) {
            if (that == null)
                return false;
            if (that == this)
                return true;
            if (that.getClass() != getClass())
                return false;
            return sortKey.equals(((UsedNonce) that).sortKey);
        }

        @Override
        public String toString() {
            return sortKey;
        }
    }
}
