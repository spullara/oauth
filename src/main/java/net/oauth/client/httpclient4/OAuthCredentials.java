/*
 * Copyright 2009 Paul Austin
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

package net.oauth.client.httpclient4;

import net.oauth.OAuthAccessor;
import org.apache.http.auth.UsernamePasswordCredentials;

/**
 * @author John Kristian
 */
public class OAuthCredentials extends UsernamePasswordCredentials {

    private final OAuthAccessor accessor;

    public OAuthCredentials(OAuthAccessor accessor) {
        super(accessor.consumer.consumerKey, accessor.consumer.consumerSecret);
        this.accessor = accessor;
    }

    public OAuthAccessor getAccessor() {
        return accessor;
    }

}
