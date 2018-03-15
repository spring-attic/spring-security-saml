/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.opensaml.compat.decoding;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;

/**
 * Decodes a message, from an inbound transport, in a binding specific manner. As the decode proceeds information is
 * stored in the {@link MessageContext}. The decoding process deserializes the message from the inbound transport into
 * its DOM representation, unmarshall the DOM into the appropriate XMLObject, and then evaluates the security policy
 * against the inbound transport and decoded message.
 *
 * Message decoders <strong>MUST</strong> must be thread safe and stateless.
 */
public interface MessageDecoder {

    /**
     * Decodes a message in a binding specific manner.
     *
     * @param messageContext current message context
     *
     * @throws MessageDecodingException thrown if the message can not be decoded
     * @throws SecurityException thrown if the decoded message does not meet the required security constraints
     */
    public void decode(MessageContext messageContext) throws MessageDecodingException, SecurityException;

}