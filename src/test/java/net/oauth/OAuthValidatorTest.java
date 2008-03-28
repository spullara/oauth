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

import junit.framework.TestCase;

public class OAuthValidatorTest extends TestCase {

    private long currentTime;
    private SimpleOAuthValidator validator;
    private static final long fiveMins = 5 * 60 * 1000L;

    @Override
    protected void setUp() throws Exception {
        validator = new SimpleOAuthValidator();
        validator.setEnvForTesting(new FakeEnv());
    }

    public void testSimpleOAuthValidator() throws Exception {
        currentTime = 43298723987L;
        long okTime = currentTime - fiveMins + 10;
        long badTime = currentTime - fiveMins - 10;
        String nonce = "lsfksdklfjfg";

        validator.validateTimestampAndNonce(okTime, nonce);

        try {
            validator.validateTimestampAndNonce(badTime, nonce);
            fail("validator should have rejected timestamp, but didn't");
        } catch (OAuthProblemException e) {
            // this is expected.
        }

        okTime = currentTime + fiveMins - 10;
        badTime = currentTime + fiveMins + 10;

        validator.validateTimestampAndNonce(okTime, nonce);

        try {
            validator.validateTimestampAndNonce(badTime, nonce);
            fail("validator should have rejected timestamp, but didn't");
        } catch (OAuthProblemException e) {
            // this is expected.
        }


        validator.validateOAuthVersion(0.9);
        validator.validateOAuthVersion(1.0);

        try {
            validator.validateOAuthVersion(1.2);
            fail("validator should have rejected version, but didn't");
        } catch (OAuthProblemException e) {
            // this is expected.
        }

        try {
            validator.validateOAuthVersion(2.0);
            fail("validator should have rejected version, but didn't");
        } catch (OAuthProblemException e) {
            // this is expected.
        }
    }

    private class FakeEnv extends SimpleOAuthValidator.Env {
        @Override
        public long getCurrentTime() {
            return currentTime;
        }
    }
}
