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
import net.oauth.client.OAuthClient;
import net.oauth.client.URLConnectionClient;
import net.unto.twitter.Api;
import net.unto.twitter.TwitterProtos.Status;

public class OAuthBuilderTest extends TestCase {

    public void testTimeline() {
        for (Status tweet : twitter.friendsTimeline().count(3).build().get()) {
            System.out.println(tweet.getCreatedAt() + " " + tweet.getUser().getName() + ": " + tweet.getText());
        }
        System.out.println("-----------------------");
        int i = 0;
        for (Status tweet : twitter.publicTimeline().build().get()) {
            System.out.println(tweet.getCreatedAt() + " " + tweet.getUser().getName() + ": " + tweet.getText());
            if (++i >= 3)
                break;
        }
    }

    private Api twitter;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        // The consumer is Bad Example:
        OAuthConsumer consumer = new OAuthConsumer(null // callback URL
                , "7y0Wxw7B9kLIVNdPAEv47g" // consumer key
                , "F34HyfNIvLTXJNgUpLSyRRdQBYYllWIMXyim6NzPQ" // consumer secret
                , OAuthBuilder.TWITTER_SERVICE_PROVIDER);
        OAuthAccessor accessor = new OAuthAccessor(consumer);
        // The user is OAuthExample:
        accessor.accessToken = "30021501-QPuaISTokIheJnGJdzyOAlYn8IuLOjchiXw03GgBt";
        accessor.tokenSecret = "lEnV6RYdraCJXZLdMJVAzXuSRDeLhuuFzzk6F2gKLg";
        twitter = new OAuthBuilder().accessor(accessor).client(new OAuthClient(new URLConnectionClient())).build();
    }

}
