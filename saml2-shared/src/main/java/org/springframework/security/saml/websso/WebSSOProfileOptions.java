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

/**
 * JavaBean contains properties allowing customization of SAML request message sent to the IDP.
 *
 * @author Vladimir Schäfer
 */
public class WebSSOProfileOptions {

    private String idp;
    private String binding;

    private boolean passive = false;
    private boolean forceAuthN = false;
    private boolean allowProxy = true;

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

    public boolean isAllowProxy() {
        return allowProxy;
    }

    public void setAllowProxy(boolean allowProxy) {
        this.allowProxy = allowProxy;
    }
}
