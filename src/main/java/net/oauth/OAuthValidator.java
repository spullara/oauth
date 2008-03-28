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

/**
 * An OAuthValidator can be passed to OAuthMessage.validateMessage to ensure
 * that the message not only has a valid signature, but also conforms to a
 * few other requirements, in particular having a correct version number
 * and a fresh timestamp, as well as a unique nonce.
 *
 * @author balfanz@google.com (Dirk Balfanz)
 */
public interface OAuthValidator {

    /**
     * Checks that the version parameter in an OAuthMessage is valid. If the
     * message did not specify an oauth_version parameter, this method will
     * be called with version=1.0.
     * @param version the version parameter found in an OAuthMessage.
     * @throws OAuthProblemException if the version was found to be invalid
     *     (e.g. too new to be handled by this library).
     */
    public void validateOAuthVersion(double version)
        throws OAuthProblemException;

    /**
     * Checks that the timestamp and nonce in an OAuthMessage are valid.
     * @param timestamp the timestamp in the message, in <b>milliseconds
     *     since Jan 1, 1970, GMT</b>.
     * @param nonce the nonce transmitted in the message, verbatim.
     * @throws OAuthProblemException if the timestamp or nonce were invalid,
     *    e.g., if the timestamp was too old, too far in the future,
     *    or if the nonce has been seen before for the same timestamp.
     */
    public void validateTimestampAndNonce(long timestamp, String nonce)
        throws OAuthProblemException;
}
