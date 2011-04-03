/* Copyright 2011 Vladimir Schafer
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

import org.opensaml.common.SAMLRuntimeException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialResolver;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.x509.X509Credential;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Set;

/**
 * Service provides management of keys used for SAML messages exchanges. CredentialResolver must accept EntityIDCriteria as its
 * credential resolver parameter. List of keys which can be queried from the store needs to be known in advance as
 * in some cases we query all available credentials.
 *
 * @author Vladimir Schafer
 */
public class ResolvingKeyManager implements KeyManager {

    private CredentialResolver credentialResolver;
    private String defaultKey;
    private Set<String> availableKeys;

    /**
     * Creates keyManager which delegates call to the inserted resolver. List of available keys is empty.
     *
     * @param credentialResolver resolver
     * @param defaultKey         default key
     */
    public ResolvingKeyManager(CredentialResolver credentialResolver, String defaultKey) {
        this(credentialResolver, defaultKey, null);
    }

    /**
     * Creates keyManager which delegates call to the inserted resolver and specifies list of available keys.
     *
     * @param credentialResolver resolver
     * @param defaultKey         default key
     * @param availableKeys      list of keys available in the resolver
     */
    public ResolvingKeyManager(CredentialResolver credentialResolver, String defaultKey, Set<String> availableKeys) {
        this.credentialResolver = credentialResolver;
        this.defaultKey = defaultKey;
        if (availableKeys == null) {
            availableKeys = Collections.emptySet();
        }
        this.availableKeys = availableKeys;
    }

    public Iterable<Credential> resolve(CriteriaSet criteriaSet) throws org.opensaml.xml.security.SecurityException {
        return credentialResolver.resolve(criteriaSet);
    }

    public Credential resolveSingle(CriteriaSet criteriaSet) throws SecurityException {
        return credentialResolver.resolveSingle(criteriaSet);
    }

    /**
     * Returns Credential object used to sign the messages issued by this entity.
     * Public, X509 and Private keys are set in the credential.
     *
     * @param keyName name of the key to use, in case of null default key is used
     * @return credential
     */
    public Credential getCredential(String keyName) {

        if (keyName == null) {
            keyName = defaultKey;
        }

        try {
            CriteriaSet cs = new CriteriaSet();
            EntityIDCriteria criteria = new EntityIDCriteria(keyName);
            cs.add(criteria);
            return resolveSingle(cs);
        } catch (org.opensaml.xml.security.SecurityException e) {
            throw new SAMLRuntimeException("Can't obtain SP signing key", e);
        }

    }

    /**
     * Returns Credential object used to sign the messages issued by this entity.
     * Public, X509 and Private keys are set in the credential.
     *
     * @return credential
     */
    public Credential getDefaultCredential() {
        return getCredential(null);
    }

    /**
     * Method provides name of the credential which should be used by default when no other is specified. It
     * must be possible to call getCredential with the returned name in order to obtain Credential value.
     *
     * @return default credential name
     */
    public String getDefaultCredentialName() {
        return defaultKey;
    }

    /**
     * Method provides list of all credentials available in the storage.
     *
     * @return available credentials
     */
    public Set<String> getAvailableCredentials() {
        return availableKeys;
    }

    /**
     * @return underlaying credentials resolver
     */
    public CredentialResolver getCredentialResolver() {
        return credentialResolver;
    }

    public X509Certificate getCertificate(String alias) {
        Credential credential = getCredential(alias);
        return ((X509Credential) credential).getEntityCertificate();
    }

}