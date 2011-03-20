package org.springframework.security.saml.key;

import org.opensaml.common.SAMLRuntimeException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialResolver;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Service provides management of keys used for SAML messages exchanges.
 */
public class KeyManager implements CredentialResolver {

    private CredentialResolver credentialResolver;
    private String defaultKey;

    /**
     * Class logger.
     */
    protected final static Logger logger = LoggerFactory.getLogger(KeyManager.class);

    public KeyManager(CredentialResolver credentialResolver, String defaultKey) {
        this.credentialResolver = credentialResolver;
        this.defaultKey = defaultKey;
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

    public String getDefaultCredentialName() {
        return defaultKey;
    }

}
