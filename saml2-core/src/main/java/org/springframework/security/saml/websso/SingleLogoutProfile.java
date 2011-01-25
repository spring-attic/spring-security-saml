/*
 * Copyright 2009 Vladimir Schaefer
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
package org.springframework.security.saml.websso;

import org.opensaml.common.SAMLException;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.validation.ValidationException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.storage.SAMLMessageStorage;

/**
 * Implementing class must contain SAML Single Logout functionality according to SAML 2.0 Profiles
 * specification.
 *
 * @author Vladimir Schaefer
 */
public interface SingleLogoutProfile {

    /**
     * Call to the method must ensure that LogoutRequest SAML message is sent to the IDP requesting global
     * logout of all known sessions.
     *
     * @param context processing context
     * @param credential     credential of the currently logged user
     * @param messageStorage storage of sent message
     *
     * @throws SAMLException             in case logout request can't be created
     * @throws MetadataProviderException in case idp metadata can't be resolved
     * @throws MessageEncodingException  in case message can't be sent using given binding
     */
    void sendLogoutRequest(SAMLMessageContext context, SAMLCredential credential, SAMLMessageStorage messageStorage) throws SAMLException, MetadataProviderException, MessageEncodingException;

    /**
     * Implementer must ensure that the incoming LogoutRequest stored in the context is verified and return true if
     * local logout should be executed. Method must send LogoutResponse message to the sender in any case.
     *
     * @param context    context containing SAML message being processed
     *
     * @param credential credential of the currently logged user
     * @return true if local logout should be performed
     *
     * @throws SAMLException             in case message is invalid and response can't be sent back
     * @throws MetadataProviderException in case there are problems with determining idp metadata
     * @throws MessageEncodingException  in case message can't be sent
     */
    boolean processLogoutRequest(SAMLMessageContext context, SAMLCredential credential) throws SAMLException, MetadataProviderException, MessageEncodingException;

    /**
     * Implementer is responsible for processing of LogoutResponse message present in the context. In case the
     * message is invalid exception should be raised, although this doesn't mean any problem to the processing,
     * as logout has already been executed.
     *
     * @param context        context containing processed SAML message
     * @param messageStorage cached previously sent messages
     *
     * @throws SAMLException       in case the received SAML message is malformed or invalid
     * @throws org.opensaml.xml.security.SecurityException
     *                             in case the signature of the message is not trusted
     * @throws ValidationException in case the signature of the message is invalid
     */
    void processLogoutResponse(SAMLMessageContext context, SAMLMessageStorage messageStorage) throws SAMLException, org.opensaml.xml.security.SecurityException, ValidationException;

}
