/* Copyright 2009-2011 Vladimir Schafer
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
package org.springframework.security.saml.key;

import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialResolver;

import java.security.cert.X509Certificate;
import java.util.Set;

/**
 * Interface defines basic service required by the SAML Extension implementation.
 *
 * @author Vladimir Schafer
 */
public interface KeyManager extends CredentialResolver {

    /**
     * Returns Credential object used to sign the messages issued by this entity.
     * Public, X509 and Private keys are set in the credential.
     *
     * @param keyName name of the key to use, in case of null default key is used
     * @return credential
     */
    public Credential getCredential(String keyName);

    /**
     * Returns Credential object used to sign the messages issued by this entity.
     * Public, X509 and Private keys are set in the credential.
     *
     * @return credential
     */
    public Credential getDefaultCredential();

    /**
     * Method provides name of the credential which should be used by default when no other is specified. It
     * must be possible to call getCredential with the returned name in order to obtain Credential value.
     *
     * @return default credential name
     */
    public String getDefaultCredentialName();

    /**
     * Method provides list of all credentials available in the storage.
     *
     * @return available credentials
     */
    public Set<String> getAvailableCredentials();

    /**
     * Returns certificate with the given alias from the keystore.
     *
     * @param alias alias of certificate to find
     * @return certificate with the given alias or null if not found
     */
    public X509Certificate getCertificate(String alias);


}