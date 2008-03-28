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

import java.util.Date;

/**
 * Default implementation of the OAuthValidator interface. A
 * SimpleOAuthValidator ignores the nonce in a message and merely
 * checks that the timestamp is not older than a certain maximum (which
 * can be specified in the constructor).
 *
 * If not specified, the default expiration time is 5 minutes, and the
 * maximum version supported is 1.0.
 *
 * @author balfanz@google.com (Dirk Balfanz)
 *
 */
public class SimpleOAuthValidator implements OAuthValidator {

    // default window for timestamps is 5 minutes
    private static final long defaultTimestampWindow = 5 * 60 * 1000L;

    private final long timestampWindow;
    private final double maxVersion;
    private Env env = new Env();

    /**
     * Public constructor. Makes a SimpleOAuthValidator that rejects messages
     * older than five minutes (or messages purporting to me more than five
     * minutes into the future), and with a OAuth version bigger than 1.0.
     */
    public SimpleOAuthValidator() {
        this(defaultTimestampWindow, Double.parseDouble(OAuth.VERSION_1_0));
    }

    /**
     * Public constructor.
     * @param timestampWindow specifies, in milliseconds, the windows (into the
     *        past and into the future) in which we'll accept timestamps..
     * @param maxVersion specifies the maximum oauth version that this validator
     *        will accept.
     */
    public SimpleOAuthValidator(long timestampWindow, double maxVersion) {
        this.timestampWindow = timestampWindow;
        this.maxVersion = maxVersion;
    }

    /** {@inherit} */
    public void validateOAuthVersion(double version)
            throws OAuthProblemException {
        if (version > maxVersion) {
            String message = new StringBuilder()
                    .append("version in message (")
                    .append(version)
                    .append(") is bigger than max expected version (")
                    .append(maxVersion)
                    .append(").")
                    .toString();
            throw new OAuthProblemException(message);
        }
    }

    /** {@inherit} */
    public void validateTimestampAndNonce(long timestamp, String nonce)
            throws OAuthProblemException {

        // we just check the timestamp age and ignore the nonce
        long now = env.getCurrentTime();
        if (Math.abs(now - timestamp) > timestampWindow) {
            String message = new StringBuilder()
                    .append("timestamp in message is too old. time now is ")
                    .append(now / 1000L)
                    .append(" timestamp is from ")
                    .append(timestamp / 1000L)
                    .append(".")
                    .toString();
            throw new OAuthProblemException(message);
        }
    }

    void setEnvForTesting(Env env) {
        this.env = env;
    }

    static class Env {
        public long getCurrentTime() {
            return new Date().getTime();
        }
    }
}
