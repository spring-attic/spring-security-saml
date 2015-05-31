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

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.util.Assert;

/**
 * SAML Token is used to pass SAMLContext object through to the SAML Authentication provider.
 *
 * @author Vladimir Schäfer
 */
public class SAMLAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 1L;

    /**
     * SAML context with content to verify
     */
    private transient SAMLMessageContext credentials;

    /**
     * Default constructor initializing the context
     *
     * @param credentials  SAML context object created after decoding
     */
    public SAMLAuthenticationToken(SAMLMessageContext credentials) {

        super(null);

        Assert.notNull(credentials, "SAMLAuthenticationToken requires the credentials parameter to be set");
        Assert.notNull(credentials, "SAMLAuthenticationToken requires the message storage parameter to be set");

        this.credentials = credentials;

        setAuthenticated(false);

    }

    /**
     * Returns the stored SAML context
     *
     * @return context
     */
    public SAMLMessageContext getCredentials() {
        return this.credentials;
    }

    /**
     * Always null
     *
     * @return null
     */
    public Object getPrincipal() {
        return null;
    }

    /**
     * This object can never be authenticated, call with true result in exception.
     *
     * @param isAuthenticated only false value allowed
     *
     * @throws IllegalArgumentException if isAuthenticated is true
     */
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        if (isAuthenticated) {
            throw new IllegalArgumentException(
                    "Cannot set this token to trusted - use constructor containing GrantedAuthority[]s instead");
        }
        super.setAuthenticated(false);
    }
    
}
