/* Copyright 2009 Vladimir Schäfer
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

import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.storage.SAMLMessageStorage;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.SAMLException;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.encryption.DecryptionException;

/**
 * @author Vladimir Schäfer
 */
public interface WebSSOProfileConsumer {

    SAMLCredential processResponse(BasicSAMLMessageContext context, SAMLMessageStorage protocolCache) throws SAMLException, org.opensaml.xml.security.SecurityException, ValidationException, DecryptionException;

}
