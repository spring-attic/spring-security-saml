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
package org.springframework.security.saml.userdetails;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;

/**
 * The SAMLUserDetailsService interface is similar to UserDetailsService with difference that SAML
 * data is used in order obtain information about the user. Implementers of the interface are
 * supposed to locate user in a arbitrary dataStore based on information present in the SAMLCredential
 * and return such a date in a form of application specific UserDetails object.
 *
 * @author Vladimir Schäfer
 */
public interface SAMLUserDetailsService {

    /**
     * The method is supposed to identify local account of user referenced by data in the SAML assertion
     * and return UserDetails object describing the user. In case the user has no local account, implementation
     * may decide to create one or just populate UserDetails object with data from assertion.
     * <p>
     * Returned object should correctly implement the getAuthorities method as it will be used to populate
     * entitlements inside the Authentication object.
     *
     * @param credential data populated from SAML message used to validate the user
     *
     * @return a fully populated user record (never <code>null</code>)
     *
     * @throws UsernameNotFoundException if the user details object can't be populated
     */
    Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException;

}
