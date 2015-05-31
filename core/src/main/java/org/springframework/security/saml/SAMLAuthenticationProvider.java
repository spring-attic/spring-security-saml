/* Copyright 2009 Vladimir Schafer
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
import org.opensaml.common.SAMLRuntimeException;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.log.SAMLLogger;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.util.Assert;

import javax.servlet.ServletException;
import java.util.*;

/**
 * Authentication provider is capable of verifying validity of a SAMLAuthenticationToken and in case
 * the token is valid to create an authenticated UsernamePasswordAuthenticationToken.
 *
 * @author Vladimir Schafer
 */
public class SAMLAuthenticationProvider implements AuthenticationProvider, InitializingBean {

    private final static Logger log = LoggerFactory.getLogger(SAMLAuthenticationProvider.class);
    private boolean forcePrincipalAsString = true;
    private boolean excludeCredential = false;
    protected WebSSOProfileConsumer consumer;
    protected WebSSOProfileConsumer hokConsumer;
    protected SAMLLogger samlLogger;
    protected SAMLUserDetailsService userDetails;

    /**
     * Attempts to perform authentication of an Authentication object. The authentication must be of type
     * SAMLAuthenticationToken and must contain filled SAMLMessageContext. If the SAML inbound message
     * in the context is valid, UsernamePasswordAuthenticationToken with name given in the SAML message NameID
     * and assertion used to verify the user as credential (SAMLCredential object) is created and set as authenticated.
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
        SAMLMessageContext context = token.getCredentials();

        if (context == null) {
            throw new AuthenticationServiceException("SAML message context is not available in the authentication token");
        }

        SAMLCredential credential;

        try {
            if (SAMLConstants.SAML2_WEBSSO_PROFILE_URI.equals(context.getCommunicationProfileId())) {
                credential = consumer.processAuthenticationResponse(context);
            } else if (SAMLConstants.SAML2_HOK_WEBSSO_PROFILE_URI.equals(context.getCommunicationProfileId())) {
                credential = hokConsumer.processAuthenticationResponse(context);
            } else {
                throw new SAMLException("Unsupported profile encountered in the context " + context.getCommunicationProfileId());
            }
        } catch (SAMLRuntimeException e) {
            log.debug("Error validating SAML message", e);
            samlLogger.log(SAMLConstants.AUTH_N_RESPONSE, SAMLConstants.FAILURE, context, e);
            throw new AuthenticationServiceException("Error validating SAML message", e);
        } catch (SAMLException e) {
            log.debug("Error validating SAML message", e);
            samlLogger.log(SAMLConstants.AUTH_N_RESPONSE, SAMLConstants.FAILURE, context, e);
            throw new AuthenticationServiceException("Error validating SAML message", e);
        } catch (ValidationException e) {
            log.debug("Error validating signature", e);
            samlLogger.log(SAMLConstants.AUTH_N_RESPONSE, SAMLConstants.FAILURE, context, e);
            throw new AuthenticationServiceException("Error validating SAML message signature", e);
        } catch (org.opensaml.xml.security.SecurityException e) {
            log.debug("Error validating signature", e);
            samlLogger.log(SAMLConstants.AUTH_N_RESPONSE, SAMLConstants.FAILURE, context, e);
            throw new AuthenticationServiceException("Error validating SAML message signature", e);
        } catch (DecryptionException e) {
            log.debug("Error decrypting SAML message", e);
            samlLogger.log(SAMLConstants.AUTH_N_RESPONSE, SAMLConstants.FAILURE, context, e);
            throw new AuthenticationServiceException("Error decrypting SAML message", e);
        }

        Object userDetails = getUserDetails(credential);
        Object principal = getPrincipal(credential, userDetails);
        Collection<? extends GrantedAuthority> entitlements = getEntitlements(credential, userDetails);

        Date expiration = getExpirationDate(credential);

        SAMLCredential authenticationCredential = excludeCredential ? null : credential;
        ExpiringUsernameAuthenticationToken result = new ExpiringUsernameAuthenticationToken(expiration, principal, authenticationCredential, entitlements);
        result.setDetails(userDetails);

        samlLogger.log(SAMLConstants.AUTH_N_RESPONSE, SAMLConstants.SUCCESS, context, result, null);

        return result;

    }

    /**
     * Populates user data from SAMLCredential into UserDetails object. By default supplied implementation of the
     * SAMLUserDetailsService is called and value of type UserDetails is returned. Users are encouraged to supply
     * implementation of this class and also include correct implementation of the getAuthorities method in it, which
     * is used to populate the entitlements inside the Authentication object.
     * <p>
     * If no SAMLUserDetailsService is specified null is returned.
     *
     * @param credential credential to load user from
     * @return user details object corresponding to the SAML credential or null if data can't be loaded
     */
    protected Object getUserDetails(SAMLCredential credential) {
        if (getUserDetails() != null) {
            return getUserDetails().loadUserBySAML(credential);
        } else {
            return null;
        }
    }

    /**
     * Method determines what will be stored as principal of the created Authentication object. By default
     * (when forcePrincipalAsString is true) string representation of the NameID returned from SAML message is used.
     * Otherwise userDetail object is used, when set, when not NameID object from the credential is returned.
     * Other implementations can be created by overriding the method.
     *
     * @param credential credential used to authenticate user
     * @param userDetail loaded user details, can be null
     * @return principal to store inside Authentication object
     */
    protected Object getPrincipal(SAMLCredential credential, Object userDetail) {
        if (isForcePrincipalAsString()) {
            return credential.getNameID().getValue();
        } else if (userDetail != null) {
            return userDetail;
        } else {
            return credential.getNameID();
        }
    }

    /**
     * Method is responsible for returning collection of users entitlements. Default implementation verifies
     * whether userDetail object is of UserDetails type and returns userDetail.getAuthorities().
     * <p>
     * In case object of other type is found empty list is returned. Users are supposed to override this
     * method to provide custom parsing is such case.
     *
     * @param credential credential used to authenticate user during SSO
     * @param userDetail user detail object returned from getUserDetails call
     * @return collection of users entitlements, mustn't be null
     */
    protected Collection<? extends GrantedAuthority> getEntitlements(SAMLCredential credential, Object userDetail) {
        if (userDetail instanceof UserDetails) {
            List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
            authorities.addAll(((UserDetails) userDetail).getAuthorities());
            return authorities;
        } else {
            return Collections.emptyList();
        }
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
     * Returns saml user details service used to load information about logged user from SAML data.
     *
     * @return service or null if not set
     */
    public SAMLUserDetailsService getUserDetails() {
        return userDetails;
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

    /**
     * The user details can be optionally set and is automatically called while user SAML assertion
     * is validated.
     *
     * @param userDetails user details
     */
    @Autowired(required = false)
    public void setUserDetails(SAMLUserDetailsService userDetails) {
        this.userDetails = userDetails;
    }

    /**
     * Logger for SAML events, cannot be null, must be set.
     *
     * @param samlLogger logger
     */
    @Autowired
    public void setSamlLogger(SAMLLogger samlLogger) {
        Assert.notNull(samlLogger, "SAMLLogger can't be null");
        this.samlLogger = samlLogger;
    }

    /**
     * Profile for consumption of processed messages, must be set.
     *
     * @param consumer consumer
     */
    @Autowired
    @Qualifier("webSSOprofileConsumer")
    public void setConsumer(WebSSOProfileConsumer consumer) {
        Assert.notNull(consumer, "WebSSO Profile Consumer can't be null");
        this.consumer = consumer;
    }

    /**
     * Profile for consumption of processed messages using the Holder-of-Key profile, must be set.
     *
     * @param hokConsumer holder-of-key consumer
     */
    @Autowired
    @Qualifier("hokWebSSOprofileConsumer")
    public void setHokConsumer(WebSSOProfileConsumer hokConsumer) {
        this.hokConsumer = hokConsumer;
    }

    public boolean isForcePrincipalAsString() {
        return forcePrincipalAsString;
    }

    /**
     * By default principal in the returned Authentication object is the NameID included in the
     * authenticated Assertion. The NameID is not serializable.
     *
     * Setting this value to true will force the NameID value to be a String.
     *
     * @param forcePrincipalAsString true to force principal to be a String
     */
    public void setForcePrincipalAsString(boolean forcePrincipalAsString) {
        this.forcePrincipalAsString = forcePrincipalAsString;
    }

    public boolean isExcludeCredential() {
        return excludeCredential;
    }

    /**
     * When false (default) the resulting Authentication object will include instance of SAMLCredential
     * as a credential value. The credential includes information related to the authentication
     * process, received attributes and is required for Single Logout.
     *
     * In case your application doesn't require the credential, it is possible to exclude it from
     * the Authentication object by setting this flag to true.
     *
     * @param excludeCredential false to include credential in the Authentication object, true to exclude it
     */
    public void setExcludeCredential(boolean excludeCredential) {
        this.excludeCredential = excludeCredential;
    }

    /**
     * Verifies that required entities were autowired or set.
     */
    public void afterPropertiesSet() throws ServletException {
        Assert.notNull(consumer, "WebSSO Profile Consumer can't be null");
        Assert.notNull(hokConsumer, "WebSSO Profile HoK Consumer can't be null");
        Assert.notNull(samlLogger, "SAMLLogger can't be null");
    }

}
