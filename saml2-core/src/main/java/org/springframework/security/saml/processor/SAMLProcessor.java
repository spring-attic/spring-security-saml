/* Copyright 2009-2011 Vladimir Schäfer
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

import org.opensaml.common.SAMLException;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.springframework.security.saml.context.SAMLMessageContext;

/**
 * Implementation is responsible for sending and receiving SAML messages using any of the supported binding. Processor
 * is unaware of the content of the messages or of the profile as part of which they're exchanged. Is is responsibility
 * of the caller to properly fill SAMLMessageContext with all required data.
 *
 * @author Vladimir Schäfer
 */
public interface SAMLProcessor {

    SAMLMessageContext retrieveMessage(SAMLMessageContext context, String binding) throws SAMLException, MetadataProviderException, MessageDecodingException, org.opensaml.xml.security.SecurityException;
    SAMLMessageContext retrieveMessage(SAMLMessageContext context) throws SAMLException, MetadataProviderException, MessageDecodingException, org.opensaml.xml.security.SecurityException;
    SAMLMessageContext sendMessage(SAMLMessageContext context, boolean sign, String binding) throws SAMLException, MetadataProviderException, MessageEncodingException;
    SAMLMessageContext sendMessage(SAMLMessageContext context, boolean sign) throws SAMLException, MetadataProviderException, MessageEncodingException;
    
}