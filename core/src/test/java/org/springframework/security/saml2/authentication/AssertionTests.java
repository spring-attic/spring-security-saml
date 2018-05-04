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

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Iterator;
import java.util.List;

import org.hamcrest.core.IsEqual;
import org.joda.time.DateTime;
import org.junit.jupiter.api.Test;
import org.springframework.security.saml2.attribute.Attribute;
import org.springframework.security.saml2.metadata.MetadataBase;
import org.springframework.security.saml2.metadata.NameId;
import org.springframework.security.saml2.signature.SignatureException;
import org.springframework.security.saml2.spi.ExamplePemKey;
import org.w3c.dom.Node;

import static java.lang.Boolean.TRUE;
import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.isEmptyOrNullString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.security.saml2.authentication.AuthenticationContextClassReference.PASSWORD_PROTECTED_TRANSPORT;
import static org.springframework.security.saml2.authentication.AuthenticationContextClassReference.UNSPECIFIED;
import static org.springframework.security.saml2.authentication.SubjectConfirmationMethod.BEARER;
import static org.springframework.security.saml2.init.Defaults.assertion;
import static org.springframework.security.saml2.init.Defaults.authenticationRequest;
import static org.springframework.security.saml2.util.XmlTestUtil.assertNodeAttribute;
import static org.springframework.security.saml2.util.XmlTestUtil.assertNodeCount;
import static org.springframework.security.saml2.util.XmlTestUtil.fromZuluTime;
import static org.springframework.security.saml2.util.XmlTestUtil.getNodes;
import static org.springframework.security.saml2.util.XmlTestUtil.toZuluTime;

public class AssertionTests extends MetadataBase {


    @Test
    public void create_with_request() throws Exception {

        AuthenticationRequest request = authenticationRequest(serviceProviderMetadata, identityProviderMetadata);
        Assertion assertion = assertion(serviceProviderMetadata, identityProviderMetadata, request);

        assertNotNull(assertion);

        assertThat(assertion.getVersion(), equalTo("2.0"));
        assertNotNull(assertion.getIssueInstant());
        assertNotNull(assertion.getId());
        assertNotNull(assertion.getIssuer());
        assertNotNull(assertion.getIssuer());
        assertThat(assertion.getIssuer().getValue(), equalTo(identityProviderMetadata.getEntityId()));

        assertNotNull(assertion.getSubject());
        assertNotNull(assertion.getSubject().getPrincipal());
        assertThat(assertion.getSubject().getPrincipal().getClass(), equalTo(NameIdPrincipal.class));
        assertThat(((NameIdPrincipal) assertion.getSubject().getPrincipal()).getSpNameQualifier(), equalTo(serviceProviderMetadata.getEntityId()));
        assertNotNull(assertion.getSubject().getConfirmations());
        assertThat(assertion.getSubject().getConfirmations().size(), equalTo(1));
        SubjectConfirmation subjectConfirmation = assertion.getSubject().getConfirmations().get(0);
        assertThat(subjectConfirmation.getMethod(), equalTo(BEARER));
        SubjectConfirmationData confirmationData = subjectConfirmation.getConfirmationData();
        assertNotNull(confirmationData);
        assertThat(confirmationData.getInResponseTo(), equalTo(request.getId()));
        assertNotNull(confirmationData.getNotBefore());
        assertNotNull(confirmationData.getNotOnOrAfter());
        assertThat(confirmationData.getRecipient(), equalTo(request.getAssertionConsumerService().getLocation()));

        Conditions conditions = assertion.getConditions();
        assertNotNull(conditions);
        assertNotNull(conditions.getNotBefore());
        assertNotNull(conditions.getNotOnOrAfter());
        assertNotNull(conditions.getCriteria());
        assertThat(conditions.getCriteria().size(), equalTo(2));
        assertThat(conditions.getCriteria().get(0).getClass(), equalTo(AudienceRestriction.class));
        assertThat(conditions.getCriteria().get(1).getClass(), equalTo(OneTimeUse.class));

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

    @Test
    public void check_xml() throws URISyntaxException, IOException {
        AuthenticationRequest request = authenticationRequest(serviceProviderMetadata, identityProviderMetadata);

        Assertion assertion = assertion(serviceProviderMetadata, identityProviderMetadata, request);

        String username = "test@test.com";

        NameIdPrincipal principal = (NameIdPrincipal) assertion.getSubject().getPrincipal();
        principal.setFormat(NameId.EMAIL);
        principal.setValue(username);

        assertion.getAuthenticationStatements().get(0).setAuthenticationContext(
            new AuthenticationContext().setClassReference(AuthenticationContextClassReference.PASSWORD_PROTECTED_TRANSPORT)
        );

        DateTime time = new DateTime(System.currentTimeMillis());
        assertion.addAttribute(
            new Attribute()
                .setFriendlyName("Random Attributes")
                .setName("rattr")
                .addValues("Filip",
                           TRUE,
                           time,
                           new Integer(54),
                           new Double("33.3"),
                           new URI("http://test.uri.com"),
                           new URL("http://test.url.com"),
                           NameId.ENTITY

                )
        );

        assertion.setSigningKey(
            identityProviderMetadata.getSigningKey(),
            identityProviderMetadata.getAlgorithm(),
            identityProviderMetadata.getDigest()
        );


        String xml = config.toXml(assertion);

        assertNotNull(xml);
        assertThat(xml, not(isEmptyOrNullString()));
        assertNodeCount(xml, "//saml:Assertion", 1);
        Iterable<Node> nodes = getNodes(xml, "//saml:Assertion");
        assertNodeAttribute(nodes.iterator().next(), "Version", IsEqual.equalTo("2.0"));
        assertNodeAttribute(nodes.iterator().next(), "IssueInstant", equalTo(toZuluTime(assertion.getIssueInstant())));
        assertNodeAttribute(nodes.iterator().next(), "ID", equalTo(assertion.getId()));

        assertNodeCount(xml, "//saml:Issuer", 1);
        nodes = getNodes(xml, "//saml:Issuer");
        assertThat(nodes.iterator().next().getTextContent(), equalTo(assertion.getIssuer().getValue()));

        assertNodeCount(xml, "//saml:Subject", 1);
        assertNodeCount(xml, "//saml:Subject/saml:NameID", 1);
        nodes = getNodes(xml, "//saml:Subject/saml:NameID");
        assertNodeAttribute(nodes.iterator().next(), "Format", equalTo(NameId.EMAIL.toString()));
        assertNodeAttribute(nodes.iterator().next(), "SPNameQualifier", equalTo(principal.getSpNameQualifier()));
        assertThat(nodes.iterator().next().getTextContent(), equalTo(assertion.getSubject().getPrincipal().getValue()));

        assertNodeCount(xml, "//saml:SubjectConfirmation", 1);
        nodes = getNodes(xml, "//saml:SubjectConfirmation");
        assertNodeAttribute(nodes.iterator().next(), "Method", equalTo(BEARER.toString()));

        assertNodeCount(xml, "//saml:SubjectConfirmation/saml:SubjectConfirmationData", 1);
        nodes = getNodes(xml, "//saml:SubjectConfirmation/saml:SubjectConfirmationData");
        assertNodeAttribute(nodes.iterator().next(), "NotOnOrAfter", equalTo(toZuluTime(assertion.getSubject().getConfirmations().get(0).getConfirmationData().getNotOnOrAfter())));
        assertNodeAttribute(nodes.iterator().next(), "InResponseTo", equalTo(assertion.getSubject().getConfirmations().get(0).getConfirmationData().getInResponseTo()));

        assertNodeCount(xml, "//saml:Conditions", 1);
        nodes = getNodes(xml, "//saml:Conditions");
        assertNodeAttribute(nodes.iterator().next(), "NotOnOrAfter", equalTo(toZuluTime(assertion.getConditions().getNotOnOrAfter())));
        assertNodeAttribute(nodes.iterator().next(), "NotBefore", equalTo(toZuluTime(assertion.getConditions().getNotBefore())));

        assertNodeCount(xml, "//saml:Conditions/saml:AudienceRestriction/saml:Audience", 1);
        nodes = getNodes(xml, "//saml:Conditions/saml:AudienceRestriction/saml:Audience");
        assertThat(nodes.iterator().next().getTextContent(), equalTo(serviceProviderMetadata.getEntityId()));

        assertNodeCount(xml, "//saml:Conditions/saml:OneTimeUse", 1);

        assertNodeCount(xml, "//saml:AuthnStatement", 1);
        nodes = getNodes(xml, "//saml:AuthnStatement");
        AuthenticationStatement authnStatement = assertion.getAuthenticationStatements().get(0);
        assertNodeAttribute(nodes.iterator().next(), "AuthnInstant", equalTo(toZuluTime(authnStatement.getAuthInstant())));
        assertNodeAttribute(nodes.iterator().next(), "SessionIndex", equalTo(authnStatement.getSessionIndex()));
        assertNodeCount(xml, "//saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef", 1);
        nodes = getNodes(xml, "//saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef");
        assertThat(nodes.iterator().next().getTextContent(), equalTo(PASSWORD_PROTECTED_TRANSPORT.toString()));


        assertNodeCount(xml, "//saml:AttributeStatement", 1);
        assertNodeCount(xml, "//saml:AttributeStatement/saml:Attribute", 1);
        nodes = getNodes(xml, "//saml:AttributeStatement/saml:Attribute");
        assertNodeAttribute(nodes.iterator().next(), "Name", equalTo("rattr"));
        assertNodeAttribute(nodes.iterator().next(), "FriendlyName", equalTo("Random Attributes"));

        assertNodeCount(xml, "//saml:AttributeStatement/saml:Attribute/saml:AttributeValue", 8);
        nodes = getNodes(xml, "//saml:AttributeStatement/saml:Attribute/saml:AttributeValue");
        Iterator<Node> iterator = nodes.iterator();
        assertThat(iterator.next().getTextContent(), equalTo("Filip"));
        assertThat(iterator.next().getTextContent(), equalTo("true"));
        assertThat(iterator.next().getTextContent(), equalTo(toZuluTime(time)));
        assertThat(iterator.next().getTextContent(), equalTo("54"));
        assertThat(iterator.next().getTextContent(), equalTo("33.3"));
        assertThat(iterator.next().getTextContent(), equalTo("http://test.uri.com"));
        assertThat(iterator.next().getTextContent(), equalTo("http://test.url.com"));
        assertThat(iterator.next().getTextContent(), equalTo(NameId.ENTITY.toString()));

        assertNodeCount(xml, "//ds:SignatureValue", 1);
        assertNodeCount(xml, "//ds:X509Certificate", 1);

    }

    @Test
    public void read_xml() throws Exception {
        byte[] data = getAssertionBytes();
        Assertion assertion = (Assertion) config.resolve(data, asList(identityProviderMetadata.getSigningKey()));

        assertNotNull(assertion);
        assertThat(assertion.getId(), equalTo("1aa4400b-d6f1-41d1-a80a-2331816b7876"));
        assertThat(assertion.getIssueInstant(), equalTo(fromZuluTime("2018-05-02T20:07:06.785Z")));
        assertThat(assertion.getVersion(), equalTo("2.0"));

        assertNotNull(assertion.getIssuer());
        assertThat(assertion.getIssuer().getValue(), equalTo("http://idp.localhost:8080/uaa"));

        assertNotNull(assertion.getSubject());
        assertNotNull(assertion.getSubject().getPrincipal());
        assertThat(assertion.getSubject().getPrincipal().getClass(), equalTo(NameIdPrincipal.class));
        NameIdPrincipal principal = (NameIdPrincipal) assertion.getSubject().getPrincipal();
        assertThat(principal.getFormat(), equalTo(NameId.EMAIL));
        assertThat(principal.getSpNameQualifier(), equalTo("http://sp.localhost:8080/uaa"));
        assertThat(principal.getValue(), equalTo("test@test.com"));

        assertNotNull(assertion.getSubject().getConfirmations());
        assertThat(assertion.getSubject().getConfirmations().size(), equalTo(1));
        assertThat(assertion.getSubject().getConfirmations().get(0).getMethod(), equalTo(BEARER));
        SubjectConfirmationData confirmationData = assertion.getSubject().getConfirmations().get(0).getConfirmationData();
        assertNotNull(confirmationData);
        assertThat(confirmationData.getInResponseTo(), equalTo("0ab65bc9-6ffc-4fce-a186-108ad42db073"));
        assertThat(confirmationData.getNotOnOrAfter(), equalTo(fromZuluTime("2018-05-02T20:09:06.785Z")));
        assertThat(confirmationData.getNotBefore(), equalTo(fromZuluTime("2018-05-02T20:06:06.785Z")));

        assertNotNull(assertion.getConditions());
        assertThat(assertion.getConditions().getNotOnOrAfter(), equalTo(fromZuluTime("2018-05-02T20:05:06.785Z")));
        assertThat(assertion.getConditions().getNotBefore(), equalTo(fromZuluTime("2018-05-02T20:06:06.785Z")));
        assertNotNull(assertion.getConditions().getCriteria());
        assertThat(assertion.getConditions().getCriteria().size(), equalTo(2));
        assertThat(assertion.getConditions().getCriteria().get(0).getClass(), equalTo(AudienceRestriction.class));
        AudienceRestriction aud = (AudienceRestriction) assertion.getConditions().getCriteria().get(0);
        assertThat(aud.getAudiences(), containsInAnyOrder("http://sp.localhost:8080/uaa"));
        assertThat(assertion.getConditions().getCriteria().get(1).getClass(), equalTo(OneTimeUse.class));

        assertNotNull(assertion.getAuthenticationStatements());
        assertThat(assertion.getAuthenticationStatements().size(), equalTo(1));
        AuthenticationStatement stmt = assertion.getAuthenticationStatements().get(0);
        assertNotNull(stmt);
        assertNotNull(stmt.getAuthInstant());
        assertNotNull(stmt.getSessionNotOnOrAfter());
        assertThat(toZuluTime(stmt.getAuthInstant()), equalTo("2018-05-02T20:07:06.785Z"));
        assertThat(toZuluTime(stmt.getSessionNotOnOrAfter()), equalTo("2018-05-02T20:37:06.785Z"));
        assertThat(stmt.getSessionIndex(), equalTo("aeb9e771-c5dd-4b9d-a5bc-71e9e0e195a9"));

        assertNotNull(stmt.getAuthenticationContext());
        assertThat(stmt.getAuthenticationContext().getClassReference(), equalTo(PASSWORD_PROTECTED_TRANSPORT));

        assertNotNull(assertion.getAttributes());
        assertThat(assertion.getAttributes().size(), equalTo(1));
        Attribute attribute = assertion.getAttributes().get(0);
        assertNotNull(attribute);
        assertThat(attribute.getFriendlyName(), equalTo("Random Attributes"));
        assertThat(attribute.getName(), equalTo("rattr"));
        assertNotNull(attribute.getValues());
        assertEquals(attribute.getValues().size(), 8);
        assertThat(attribute.getValues().get(0), equalTo("Filip"));
        assertThat(attribute.getValues().get(1), equalTo(TRUE));
        assertThat(attribute.getValues().get(2), equalTo(fromZuluTime("2018-05-02T20:07:06.785Z")));
        assertThat(attribute.getValues().get(3), equalTo(54));
        assertThat(attribute.getValues().get(4), equalTo("33.3"));
        assertThat(attribute.getValues().get(5), equalTo(new URI("http://test.uri.com")));
        assertThat(attribute.getValues().get(6), equalTo(new URI("http://test.url.com")));
        assertThat(attribute.getValues().get(7), equalTo("urn:oasis:names:tc:SAML:2.0:nameid-format:entity"));

        //assertNotNull(assertion.getSignature());


    }

    @Test
    public void unable_to_verify_signature() throws Exception {
        byte[] data = getAssertionBytes();
        Exception expected =
            assertThrows(
                SignatureException.class,
                //using the wrong key
                () -> config.resolve(data, asList(ExamplePemKey.SP_RSA_KEY.getPublicKey("verify")))
            );
        assertThat(expected.getMessage(), equalTo("Signature cryptographic validation not successful"));
    }

    protected byte[] getAssertionBytes() throws IOException {
        return getFileBytes("/test-data/assertion/assertion-local-20180502.xml");
    }


}
