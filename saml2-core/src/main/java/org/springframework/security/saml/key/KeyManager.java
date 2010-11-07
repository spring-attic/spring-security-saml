package org.springframework.security.saml.key;

import org.opensaml.common.SAMLRuntimeException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialResolver;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Iterator;

/**
 * Service provides management of keys used for SAML messages exchanges.
 */
public class KeyManager implements CredentialResolver {

    private CredentialResolver credentialResolver;
    private String signingKey;

    /**
     * Class logger.
     */
    protected final static Logger logger = LoggerFactory.getLogger(KeyManager.class);

    public KeyManager(CredentialResolver credentialResolver, String signingKey) {
        this.credentialResolver = credentialResolver;
        this.signingKey = signingKey;
    }

    public Credential getServerCredential(String entityID) throws org.opensaml.xml.security.SecurityException {
        CriteriaSet cs = new CriteriaSet();
        EntityIDCriteria criteria = new EntityIDCriteria(entityID);
        cs.add(criteria);
        Iterator<Credential> credentialIterator = credentialResolver.resolve(cs).iterator();
        if (credentialIterator.hasNext()) {
            return credentialIterator.next();
        } else {
            logger.error("Key with ID '" + entityID + "' wasn't found in the configured key store");
            throw new SAMLRuntimeException("Key with ID '" + entityID + "' wasn't found in the configured key store");
        }
    }

    public Iterable<Credential> resolve(CriteriaSet criteriaSet) throws org.opensaml.xml.security.SecurityException {
        return credentialResolver.resolve(criteriaSet);
    }

    public Credential resolveSingle(CriteriaSet criteriaSet) throws SecurityException {
        return credentialResolver.resolveSingle(criteriaSet);
    }

    /**
     * Returns Credential object used to sign the message issued by this entity.
     * Public, X509 and Private keys are set in the credential.
     *
     * @return credential
     */
    public Credential getSPSigningCredential() {
        try {
            CriteriaSet cs = new CriteriaSet();
            EntityIDCriteria criteria = new EntityIDCriteria(signingKey);
            cs.add(criteria);
            return resolveSingle(cs);
        } catch (org.opensaml.xml.security.SecurityException e) {
            throw new SAMLRuntimeException("Can't obtain SP signing key", e);
        }
    }

}
