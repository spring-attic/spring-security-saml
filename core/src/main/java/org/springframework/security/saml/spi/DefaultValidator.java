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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import org.joda.time.DateTime;
import org.joda.time.Interval;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.ValidationResult;
import org.springframework.security.saml.ValidationResult.ValidationError;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.authentication.Issuer;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.authentication.StatusCode;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.saml2.signature.Signature;
import org.springframework.security.saml.saml2.signature.SignatureException;

import static org.springframework.security.saml.saml2.metadata.NameId.ENTITY;
import static org.springframework.util.StringUtils.hasText;

public class DefaultValidator implements SamlValidator {

    private SpringSecuritySaml implementation;
    private int responseSkewTimeSeconds = 120;
    private boolean allowUnsolicitedResponses = true;

    public DefaultValidator(SpringSecuritySaml implementation) {
        setImplementation(implementation);
    }

    private void setImplementation(SpringSecuritySaml implementation) {
        this.implementation = implementation;
    }

    public int getResponseSkewTimeSeconds() {
        return responseSkewTimeSeconds;
    }

    public DefaultValidator setResponseSkewTimeSeconds(int responseSkewTimeSeconds) {
        this.responseSkewTimeSeconds = responseSkewTimeSeconds;
        return this;
    }

    public boolean isAllowUnsolicitedResponses() {
        return allowUnsolicitedResponses;
    }

    public DefaultValidator setAllowUnsolicitedResponses(boolean allowUnsolicitedResponses) {
        this.allowUnsolicitedResponses = allowUnsolicitedResponses;
        return this;
    }

    @Override
    public Signature validateSignature(Saml2Object saml2Object, List<SimpleKey> verificationKeys)
        throws SignatureException {
        try {
            return implementation.validateSignature(saml2Object, verificationKeys);
        } catch (Exception x) {
            if (x instanceof SignatureException) {
                throw x;
            } else {
                throw new SignatureException(x.getMessage(), x);
            }
        }
    }

    @Override
    public ValidationResult validate(Saml2Object saml2Object) {
        return null;
    }


    protected ValidationResult validate(Response response,
                                        List<String> mustMatchInResponseTo,
                                        ServiceProviderMetadata requester,
                                        IdentityProviderMetadata responder) {
        if (response == null) {
            return new ValidationResult().addError(new ValidationError("Response is null"));
        }

        if (response.getStatus() == null || response.getStatus().getCode() == null) {
            return new ValidationResult().addError(new ValidationError("Response status or code is null"));
        }

        StatusCode statusCode = response.getStatus().getCode();
        if (statusCode != StatusCode.SUCCESS) {
            return new ValidationResult().addError(
                new ValidationError("An error response was returned: " + statusCode.toString())
            );
        }

        if (response.getSignature() != null && !response.getSignature().isValidated()) {
            return new ValidationResult().addError(new ValidationError("No validated signature present"));
        }

        //verify issue time
        DateTime issueInstant = response.getIssueInstant();
        if (!isDateTimeSkewValid(getResponseSkewTimeSeconds(), 0, issueInstant)) {
            return new ValidationResult().addError(new ValidationError("Response issue time is either too old or in the future"));
        }

        //validate InResponseTo
        String replyTo = response.getInResponseTo();
        if (!isAllowUnsolicitedResponses() && !hasText(replyTo)) {
            return new ValidationResult().addError(new ValidationError("InResponseTo is missing and unsolicited responses are disabled"));
        }

        if (hasText(replyTo) && !mustMatchInResponseTo.contains(replyTo)) {
            return new ValidationResult().addError(new ValidationError("Invalid InResponseTo ID, not found in supplied list"));
        }

        //validate destination
        if (!compareURIs(requester.getServiceProvider().getAssertionConsumerService(), response.getDestination())) {
            return new ValidationResult().addError(new ValidationError("Destination mismatch: " + response.getDestination()));
        }

        //validate issuer
        //name id if not null should be "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
        //value should be the entity ID of the responder
        Issuer issuer = response.getIssuer();
        if (issuer != null) {
            if (!requester.getEntityId().equals(issuer.getValue())) {
                return new ValidationResult()
                    .addError(
                        new ValidationError(
                            String.format("Issuer mismatch. Expected: %s Actual: %s",
                                          requester.getEntityId(), issuer.getValue())
                        )
                    );
            }
            if (issuer.getFormat() != null && !issuer.getFormat().equals(ENTITY)) {
                return new ValidationResult()
                    .addError(
                        new ValidationError(
                            String.format("Issuer name format mismatch. Expected: %s Actual: %s",
                                          ENTITY, issuer.getFormat())
                        )
                    );
            }
        }

        //DECRYPT ENCRYPTED ASSERTIONS

        //verify assertion
        //issuer
        //signature

        //verify assertion subject for BEARER
        //for each subject confirmation
        //1. data must not be null
        //2. NotBefore must be null (saml-profiles-2.0-os 558)
        //3. NotOnOfAfter must not be null and within skew
        //4. InResponseTo if it exists
        //5. Recipient must match ACS URL
        //6. DECRYPT NAMEID if it is encrypted
        //6b. Use regular NameID


        //VERIFY authentication statements

        //VERIFY conditions

        return new ValidationResult();

    }

    protected boolean isDateTimeSkewValid(int skewMillis, int forwardMillis, DateTime time) {
        if (time == null) {
            return false;
        }
        final DateTime reference = new DateTime();
        final Interval validTimeInterval = new Interval(
            reference.minusMillis(skewMillis + forwardMillis),
            reference.plusMillis(skewMillis)
        );
        return validTimeInterval.contains(time);
    }

    protected boolean compareURIs(List<Endpoint> endpoints, String uri) {
        for (Endpoint ep : endpoints) {
            if (compareURIs(ep.getLocation(), uri)) {
                return true;
            }
        }
        return false;
    }

    protected boolean compareURIs(String uri1, String uri2) {
        if (uri1 == null && uri2 == null) {
            return true;
        }
        try {
            new URI(uri1);
            new URI(uri2);
            return removeQueryString(uri1).equalsIgnoreCase(removeQueryString(uri2));
        } catch (URISyntaxException e) {
            return false;
        }
    }

    public String removeQueryString(String uri) {
        int queryStringIndex = uri.indexOf('?');
        if (queryStringIndex >= 0) {
            return uri.substring(0, queryStringIndex);
        }
        return uri;
    }
}
