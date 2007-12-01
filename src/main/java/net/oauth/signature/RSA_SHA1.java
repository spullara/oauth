/*
 * Copyright 2007 Google, Inc.
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

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import net.oauth.OAuth;
import net.oauth.OAuthConsumer;

/**
 * Class to handle RSA-SHA1 signatures on OAuth requests. A consumer 
 * that wishes to use public-key signatures on messages does not need
 * a shared secret with the service provider, but it needs a private
 * RSA signing key. You create it like this:
 * 
 * OAuthConsumer c = new OAuthConsumer(callback_url, consumer_key, 
 *                                     null, provider);
 * c.setProperty(JceRSA_SHA1.PRIVATE_KEY, consumer_privateRSAKey);
 * 
 * (consumer_privateRSAKey must be an RSA signing key and 
 * of type java.security.PrivateKey )
 * 
 * A service provider that wishes to verify signatures made by such a 
 * consumer does not need a shared secret with the consumer, but it needs
 * to know the consumer's public key. You create the necessary 
 * OAuthConsumer object (on the service provider's side) like this:
 * 
 * OAuthConsumer c = new OAuthConsumer(callback_url, consumer_key, 
 *                                     null, provider);
 * c.setProperty(JceRSA_SHA1.PUBLIC_KEY, consumer_publicRSAKey);
 * 
 * (consumer_publicRSAKey must be the consumer's public RSAkey and 
 * of type java.security.PublicKey)
 * 
 * @author Dirk Balfanz 
 *
 */
public class RSA_SHA1 extends OAuthSignatureMethod {

    final static public String PUBLIC_KEY = "RSA-SHA1.JcePublicKey";
    final static public String PRIVATE_KEY = "RSA-SHA1.JcePrivateKey ";

    private PrivateKey privateKey;
    private PublicKey publicKey;
    
    @Override
    protected void initialize(String name, OAuthConsumer consumer)
            throws Exception { 
        super.initialize(name, consumer);
        privateKey = (PrivateKey)consumer.getProperty(PRIVATE_KEY);
        publicKey = (PublicKey)consumer.getProperty(PUBLIC_KEY);
    }
    
    @Override 
    protected String getSignature(String baseString) throws Exception {
        byte[] signature = sign(baseString.getBytes());
        return urlEncode(base64Encode(signature));
    }

    @Override 
    protected boolean isValid(String signature, String baseString)
        throws Exception {
        return verify(decodeBase64(urlDecode(signature)),
                      baseString.getBytes());
    } 
    
    private byte[] sign(byte[] message) throws GeneralSecurityException {
        if (privateKey == null) {
            throw new IllegalStateException("need to set private key with " + 
                                            "OAuthConsumer.setProperty when " +
                                            "generating RSA-SHA1 signatures.");
        }
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(privateKey);
        signer.update(message);
        return signer.sign();
    }

    private boolean verify(byte[] signature, byte[] message) 
            throws GeneralSecurityException {
        if (publicKey == null) {
            throw new IllegalStateException("need to set public key with " + 
                                            " OAuthConsumer.setProperty when " +
                                            "verifying RSA-SHA1 signatures.");
        }
        Signature verifier = Signature.getInstance("SHA1withRSA"); 
        verifier.initVerify(publicKey);
        verifier.update(message);
        return verifier.verify(signature);
    }
    
    private static String urlEncode(String string) {
        return OAuth.percentEncode(string);
    }
    
    private static String urlDecode(String string) {
        return OAuth.decodePercent(string);
    }  
}
