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

/**
 * @author Dirk Balfanz
 * @author John Kristian
 */
public class OAuthValidatorTest extends TestCase {

    private long currentTime;
    private SimpleOAuthValidator validator;

    @Override
    protected void setUp() throws Exception {
        currentTime = System.currentTimeMillis() / 1000;
        validator = new SimpleOAuthValidator();
        validator.setEnvForTesting(new FakeEnv());
    }

    public void testSimpleOAuthValidator() throws Exception {
        final long window = SimpleOAuthValidator.DEFAULT_TIMESTAMP_WINDOW;
        tryTimestamp(currentTime - window + 1);
        tryTimestamp(currentTime + window - 1);
        try {
            tryTimestamp(currentTime - window - 1);
            fail("validator should have rejected timestamp, but didn't");
        } catch (OAuthProblemException expected) {
        }
        try {
            tryTimestamp(currentTime + window + 1);
            fail("validator should have rejected timestamp, but didn't");
        } catch (OAuthProblemException expected) {
        }

        tryVersion(1.0);
        try {
            tryVersion(0.9);
            fail("validator should have rejected version, but didn't");
        } catch (OAuthProblemException expected) {
        }
        try {
            tryVersion(1.2);
            fail("validator should have rejected version, but didn't");
        } catch (OAuthProblemException expected) {
        }
        try {
            tryVersion(2.0);
            fail("validator should have rejected version, but didn't");
        } catch (OAuthProblemException expected) {
        }
    }

    private void tryTimestamp(long timestamp) throws Exception {
        OAuthMessage msg = new OAuthMessage("", "", OAuth.newList(
                "oauth_timestamp", timestamp + "",
                "oauth_nonce", "lsfksdklfjfg"));
        validator.validateTimestampAndNonce(msg);
    }

    private void tryVersion(double version) throws Exception {
        OAuthMessage msg = new OAuthMessage("", "", OAuth.newList(
                "oauth_version", version + ""));
        validator.validateVersion(msg);
    }

    private class FakeEnv extends SimpleOAuthValidator.Env {
        @Override
        public long currentTime() {
            return currentTime;
        }
    }
}
