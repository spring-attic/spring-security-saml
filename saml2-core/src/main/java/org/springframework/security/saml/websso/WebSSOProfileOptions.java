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
package org.springframework.security.saml.websso;

import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;

import java.io.Serializable;
import java.util.Collection;

/**
 * JavaBean contains properties allowing customization of SAML request message sent to the IDP.
 *
 * @author Vladimir Schafer
 */
public class WebSSOProfileOptions implements Serializable, Cloneable {

    private String idp;
    private String binding;

    // Name ID policy
    private String nameID;
    private boolean allowCreate;

    private boolean passive = false;
    private boolean forceAuthN = false;
    private boolean includeScoping = true;
    private boolean allowProxy = true;

    private Collection<String> authnContexts;
    private AuthnContextComparisonTypeEnumeration authnContextComparison = AuthnContextComparisonTypeEnumeration.EXACT;

    public WebSSOProfileOptions() {
    }

    public WebSSOProfileOptions(String idp, String binding) {
        this.idp = idp;
        this.binding = binding;
    }

    public String getIdp() {
        return idp;
    }

    public void setIdp(String idp) {
        this.idp = idp;
    }

    public String getBinding() {
        return binding;
    }

    /**
     * Sets binding to be used for connection to IDP and back. Following values are supported:
     * "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect".
     *
     * @param binding binding value
     * @see org.opensaml.common.xml.SAMLConstants#SAML2_POST_BINDING_URI
     * @see org.opensaml.common.xml.SAMLConstants#SAML2_REDIRECT_BINDING_URI
     */
    public void setBinding(String binding) {
        this.binding = binding;
    }

    /**
     * Sets whether the IdP should refrain from interacting with the user during the authentication process. Boolean
     * values will be marshalled to either "true" or "false".
     *
     * @return true if passive authentication is allowed, false otherwise
     */
    public boolean getPassive() {
        return passive;
    }

    public void setPassive(Boolean passive) {
        this.passive = passive;
    }

    public boolean getForceAuthN() {
        return forceAuthN;
    }

    public void setForceAuthN(Boolean forceAuthN) {
        this.forceAuthN = forceAuthN;
    }

    /**
     * True if scoping element should be included in the requests sent to IDP.
     *
     * @return true if scoping should be included
     */
    public boolean isIncludeScoping() {
        return includeScoping;
    }

    public void setIncludeScoping(boolean includeScoping) {
        this.includeScoping = includeScoping;
    }

    /**
     * True is proxying should be allowed in requests sent to IDP as part of the generated Scoping element.
     * Property includeScoping must be enabled for this value to take any effect.
     *
     * @return true if proxying is allowed
     */
    public boolean isAllowProxy() {
        return allowProxy;
    }

    public void setAllowProxy(boolean allowProxy) {
        this.allowProxy = allowProxy;
    }

    public Collection<String> getAuthnContexts() {
        return authnContexts;
    }

    public void setAuthnContexts(Collection<String> authnContexts) {
        this.authnContexts = authnContexts;
    }

    /**
     * Clones the current object.
     *
     * @return clone
     */
    @Override
    public WebSSOProfileOptions clone() {
        try {
            return (WebSSOProfileOptions) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException("Invalid cloning support", e);
        }
    }

    public String getNameID() {
        return nameID;
    }

    public void setNameID(String nameID) {
        this.nameID = nameID;
    }

    public boolean isAllowCreate() {
        return allowCreate;
    }

    public void setAllowCreate(boolean allowCreate) {
        this.allowCreate = allowCreate;
    }

    /**
     * @return comparison mode to use by default mode minimum is used
     */
    public AuthnContextComparisonTypeEnumeration getAuthnContextComparison() {
        return authnContextComparison;
    }

    /**
     * Sets comparison to use for WebSSO requests. No change for null values.
     *
     * @param authnContextComparison context to set
     */
    public void setAuthnContextComparison(AuthnContextComparisonTypeEnumeration authnContextComparison) {
        if (authnContextComparison != null) {
            this.authnContextComparison = authnContextComparison;
        }
    }
    
}
