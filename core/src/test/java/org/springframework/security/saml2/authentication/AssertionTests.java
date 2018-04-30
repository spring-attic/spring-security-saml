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

package org.springframework.security.saml2.authentication;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.security.saml2.attribute.Attribute;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.security.saml2.authentication.AuthenticationContextClassReference.UNSPECIFIED;
import static org.springframework.security.saml2.authentication.SubjectConfirmationMethod.BEARER;
import static org.springframework.security.saml2.init.Defaults.assertion;
import static org.springframework.security.saml2.init.Defaults.authenticationRequest;

public class AssertionTests extends AuthenticationTests {

    @Test
    public void create_with_request() throws Exception {

        AuthenticationRequest request = authenticationRequest(serviceProviderMetadata, identityProviderMetadata);
        Assertion assertion = assertion(serviceProviderMetadata, identityProviderMetadata, request);

        assertNotNull(assertion);

        assertThat(assertion.getVersion(), equalTo("2.0"));
        assertNotNull(assertion.getIssueInstant());
        assertNotNull(assertion.getId());
        assertNotNull(assertion.getIssuer());
        assertThat(assertion.getIssuer(), equalTo(identityProviderMetadata.getEntityId()));

        assertNotNull(assertion.getSubject());
        assertNotNull(assertion.getSubject().getPrincipal());
        assertThat(assertion.getSubject().getPrincipal().getClass(), equalTo(NameIdPrincipal.class));
        assertNotNull(assertion.getSubject().getConfirmation());
        assertThat(assertion.getSubject().getConfirmation().getMethod(), equalTo(BEARER));

        SubjectConfirmationData confirmationData = assertion.getSubject().getConfirmation().getConfirmationData();
        assertNotNull(confirmationData);
        assertThat(confirmationData.getInResponseTo(),equalTo(request.getId()));
        assertNotNull(confirmationData.getNotBefore());
        assertNotNull(confirmationData.getNotOnOrAfter());
        assertThat(confirmationData.getRecipient(), equalTo(request.getAssertionConsumerService().getLocation()));

        Conditions conditions = assertion.getConditions();
        assertNotNull(conditions);
        assertNotNull(conditions.getNotBefore());
        assertNotNull(conditions.getNotOnOrAfter());
        assertNotNull(conditions.getConditions());
        assertThat(conditions.getConditions().size(), equalTo(2));
        assertThat(conditions.getConditions().get(0).getClass(), equalTo(AudienceRestriction.class));
        assertThat(conditions.getConditions().get(1).getClass(), equalTo(OneTimeUse.class));

        List<AuthenticationStatement> statements = assertion.getAuthenticationStatements();
        assertNotNull(statements);
        assertThat(statements.size(), equalTo(1));

        AuthenticationStatement statement = statements.get(0);
        assertNotNull(statement);
        assertNotNull(statement.getAuthInstant());
        assertNotNull(statement.getSessionIndex());
        assertNotNull(statement.getSessionNotOnOrAfter());

        AuthenticationContext authenticationContext = statement.getAuthenticationContext();
        assertNotNull(authenticationContext);
        assertThat(authenticationContext.getClassReference(), equalTo(UNSPECIFIED));

        List<Attribute> attributes = assertion.getAttributes();
        assertNotNull(attributes);
        assertThat(attributes.size(), equalTo(0));

    }


}
