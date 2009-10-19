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
package org.springframework.security.saml;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLException;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.encryption.DecryptionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.AuthenticationServiceException;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.providers.AbstractAuthenticationToken;
import org.springframework.security.providers.AuthenticationProvider;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.saml.storage.SAMLMessageStorage;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;

import java.util.Date;
import java.util.List;

/**
 * Authentication provider is capable of verifying validity of a SAMLAuthenticationToken and in case
 * the token is valid to create an authenticated UsernamePasswordAuthenticationToken.
 *
 * @author Vladimir Schäfer
 */
public class SAMLAuthenticationProvider implements AuthenticationProvider {

    private WebSSOProfileConsumer consumer;

    private final static Logger log = LoggerFactory.getLogger(SAMLAuthenticationProvider.class);
    private SAMLUserDetailsService userDetails;

    /**
     * Default constructor
     *
     * @param consumer profile to use
     */
    public SAMLAuthenticationProvider(WebSSOProfileConsumer consumer) {
        this.consumer = consumer;
    }

    /**
     * Attempts to perform authentication of an Authentication object. The authentication must be of type
     * SAMLAuthenticationToken and must contain filled BasicSAMLMessageContext. If the SAML inbound message
     * in the context is valid, UsernamePasswordAuthenticationToken with name given in the SAML message NameID
     * and assertion used to verify the user as credential are created and set as authenticated.
     *
     * @param authentication SAMLAuthenticationToken to verify
     * @return UsernamePasswordAuthenticationToken with name as NameID value and SAMLCredential as credential object
     * @throws AuthenticationException user can't be authenticated due to an error
     */
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        if (!supports(authentication.getClass())) {
            throw new IllegalArgumentException("Only SAMLAuthenticationToken is supported, " + authentication.getClass() + " was attempted");
        }

        SAMLAuthenticationToken token = (SAMLAuthenticationToken) authentication;
        SAMLMessageStorage store = token.getMessageStore();
        BasicSAMLMessageContext context = token.getCredentials();
        SAMLCredential credential;

        try {
            credential = consumer.processResponse(context, store);
        } catch (SAMLException e) {
            throw new AuthenticationServiceException("Error validating SAML message", e);
        } catch (ValidationException e) {
            log.debug("Error validating signature", e);
            throw new AuthenticationServiceException("Error validating SAML message signature", e);
        } catch (org.opensaml.xml.security.SecurityException e) {
            log.debug("Error validating signature", e);
            throw new AuthenticationServiceException("Error validating SAML message signature", e);
        } catch (DecryptionException e) {
            log.debug("Error decrypting SAML message", e);
            throw new AuthenticationServiceException("Error decrypting SAML message", e);
        }

        String name = credential.getNameID().getValue();
        Date expiration = getExpirationDate(credential);
        ExpiringUsernameAuthenticationToken result = new ExpiringUsernameAuthenticationToken(expiration, name, credential, new GrantedAuthority[0]);
        processUserDetails(result, credential);
        return result;
        
    }

    /**
     * Parses the SAMLCredential for expiration time. Locates all AuthnStatements present within the assertion
     * (only one in most cases) and computes the expiration based on sessionNotOnOrAfter field.
     *
     * @param credential credential to use for expiration parsing.
     * @return null if no expiration is present, expiration time onOrAfter which the token is not valid anymore
     */
    protected Date getExpirationDate(SAMLCredential credential) {
        List<AuthnStatement> statementList = credential.getAuthenticationAssertion().getAuthnStatements();
        DateTime expiration = null;
        for (AuthnStatement statement : statementList) {
            DateTime newExpiration = statement.getSessionNotOnOrAfter();
            if (newExpiration != null) {
                if (expiration == null || expiration.isAfter(newExpiration)) {
                    expiration = newExpiration;
                }
            }
        }
        return expiration != null ? expiration.toDate() : null;
    }

    /**
     * Populates user data from SAMLCredential into UserDetails object.
     *
     * @param token      token to store UserDetails to
     * @param credential credential to load user from
     */
    protected void processUserDetails(AbstractAuthenticationToken token, SAMLCredential credential) {
        if (getUserDetails() != null) {
            token.setDetails(getUserDetails().loadUserBySAML(credential));
        }
    }

    /**
     * Returns saml user details service used to load information about logged user from SAML data.
     *
     * @return service or null if not set
     */
    public SAMLUserDetailsService getUserDetails() {
        return userDetails;
    }

    /**
     * The user details can be optionally set and is automatically called while user SAML assertion
     * is validated.
     *
     * @param userDetails user details
     */
    public void setUserDetails(SAMLUserDetailsService userDetails) {
        this.userDetails = userDetails;
    }

    /**
     * SAMLAuthenticationToken is the only supported token.
     *
     * @param aClass class to check for support
     * @return true if class is of type SAMLAuthenticationToken
     */
    public boolean supports(Class aClass) {
        return SAMLAuthenticationToken.class.isAssignableFrom(aClass);
    }

}
