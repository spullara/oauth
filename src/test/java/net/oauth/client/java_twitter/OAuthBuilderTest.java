/*
 * Copyright 2009 John Kristian
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

package net.oauth.client.java_twitter;

import junit.framework.TestCase;
import net.oauth.OAuthAccessor;
import net.oauth.OAuthConsumer;
import net.unto.twitter.Api;
import net.unto.twitter.TwitterProtos.Status;
import net.unto.twitter.methods.FriendsTimelineRequest;

public class OAuthBuilderTest extends TestCase {

    /** Get friends' and public timelines. */
    public void testTimeline() {
        Api api = builder.build();
        for (Status tweet : api.friendsTimeline().count(3).build().get()) {
            System.out.println(tweet.getCreatedAt() + " " + tweet.getUser().getName() + ": " + tweet.getText());
        }
        System.out.println("-----------------------");
        int i = 0;
        for (Status tweet : api.publicTimeline().build().get()) {
            System.out.println(tweet.getCreatedAt() + " " + tweet.getUser().getName() + ": " + tweet.getText());
            if (++i >= 3)
                break;
        }
    }

    /** Use the wrong secret to sign a request. */
    public void testWrongSecret() {
        accessor.tokenSecret += "-";
        Api api = builder.build();
        FriendsTimelineRequest request = api.friendsTimeline().build();
        try {
            request.get();
            fail(request + ".get");
        } catch (SecurityException expected) {
        }
    }

    /** Use no access token to build a request. */
    public void testNoCredentials() {
        accessor.accessToken = null;
        accessor.tokenSecret = null;
        FriendsTimelineRequest.Builder b = builder.build().friendsTimeline();
        try {
            b.build();
            fail(b + ".build");
        } catch (IllegalStateException expected) {
        }
    }

    private OAuthAccessor accessor;
    private OAuthBuilder builder;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        // The consumer is Bad Example:
        OAuthConsumer consumer = new OAuthConsumer(null // callback URL
                , "7y0Wxw7B9kLIVNdPAEv47g" // consumer key
                , "F34HyfNIvLTXJNgUpLSyRRdQBYYllWIMXyim6NzPQ" // consumer secret
                , OAuthBuilder.TWITTER_SERVICE_PROVIDER);
        accessor = new OAuthAccessor(consumer);
        // The user is OAuthExample:
        accessor.accessToken = "30021501-ZxbRk1MlGZbfVi4FCLgQGTAZSFzgoIlgohC6kg7E";
        accessor.tokenSecret = "G6PaFWdZtbuBu9ywfmKCgj0PrLxGLkOgUU2zMvJzk";
        builder = new OAuthBuilder().accessor(accessor);
    }

}
