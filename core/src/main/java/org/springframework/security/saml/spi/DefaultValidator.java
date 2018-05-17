/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.springframework.security.saml.spi;

import java.util.List;

import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.ValidationResult;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.signature.Signature;
import org.springframework.security.saml.saml2.signature.SignatureException;

public class DefaultValidator implements SamlValidator {

    private SpringSecuritySaml implementation;

    public DefaultValidator(SpringSecuritySaml implementation) {
        setImplementation(implementation);
    }

    private void setImplementation(SpringSecuritySaml implementation) {
        this.implementation = implementation;
    }


    @Override
    public Signature validateSignature(Saml2Object saml2Object, List<SimpleKey> verificationKeys)
        throws SignatureException {
        return implementation.validateSignature(saml2Object, verificationKeys);
    }

    @Override
    public ValidationResult validate(Saml2Object saml2Object) {
        return null;
    }
}
