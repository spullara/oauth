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

/**
 * Properties of one User of an OAuthConsumer.
 * 
 * @author John Kristian
 */
public class OAuthAccessor {

    public final OAuthConsumer consumer;

    public String requestToken;

    public String accessToken;

    public String tokenSecret;
    
    public boolean authorized = false;
    
    public Object user;

    public OAuthAccessor(OAuthConsumer consumer) {
        this.consumer = consumer;
        this.requestToken = null;
        this.accessToken = null;
        this.tokenSecret = null;
        user = null;
    }
    
    public Object getUser(){
        return user;
    }
    
    public void setUser(Object user){
        this.user = user;
    }
    
    public boolean isAuthorized(){
        return authorized;
    }
    
    public void setAuthorized(){
        this.authorized = true;
    }
}
