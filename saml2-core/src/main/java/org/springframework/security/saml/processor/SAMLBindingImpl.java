/* Copyright 2010 Vladimir Schaefer
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
package org.springframework.security.saml.processor;

import org.opensaml.Configuration;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.ws.message.decoder.MessageDecoder;
import org.opensaml.ws.message.encoder.MessageEncoder;
import org.opensaml.ws.security.SecurityPolicyRule;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.security.credential.ChainingCredentialResolver;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.MetadataManager;

import java.util.List;

/**
 * Implementation contains a static decoder instance returned in case conditions specified in
 * the subclass are satisfied.
 *
 * @author Vladimir Schaefer
 */
public abstract class SAMLBindingImpl implements SAMLBinding {

    @Autowired
    KeyManager keyManager;

    @Autowired
    MetadataManager metadata;

    @Autowired
    ParserPool parserPool;

    MessageDecoder decoder;
    MessageEncoder encoder;

    protected SAMLBindingImpl(MessageDecoder decoder, MessageEncoder encoder) {
        this.decoder = decoder;
        this.encoder = encoder;
    }

    public MessageDecoder getMessageDecoder() {
        return decoder;
    }

    public MessageEncoder getMessageEncoder() {
        return encoder;
    }

    public void getSecurityPolicy(List<SecurityPolicyRule> securityPolicy, BasicSAMLMessageContext samlContext) {
    }

    protected ChainingCredentialResolver getDefaultCredentialResolver() {

        ChainingCredentialResolver chainedResolver = new ChainingCredentialResolver();
        chainedResolver.getResolverChain().add(new MetadataCredentialResolver(metadata));
        chainedResolver.getResolverChain().add(keyManager);
        return chainedResolver;

    }

    protected SignatureTrustEngine getDefaultSignatureTrustEngine() {

        KeyInfoCredentialResolver keyInfoCredResolver = Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver();
        ChainingCredentialResolver resolver = getDefaultCredentialResolver();
        return new ExplicitKeySignatureTrustEngine(resolver, keyInfoCredResolver);

    }

}