package org.springframework.security.saml.websso;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.*;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.schema.XSString;

import java.util.Collection;

/**
 * Helper class for creation of SAML parts for testing.
 */
public class WebSSOProfileTestHelper {

    XMLObjectBuilderFactory builderFactory;

    public WebSSOProfileTestHelper(XMLObjectBuilderFactory builderFactory) {
        this.builderFactory = Configuration.getBuilderFactory();
    }

    public Response getValidResponse() {
        SAMLObjectBuilder<Response> builder = (SAMLObjectBuilder<Response>) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);
        Response response = builder.buildObject();

        StatusCode statusCode = ((SAMLObjectBuilder<StatusCode>) builderFactory.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME)).buildObject();
        statusCode.setValue(StatusCode.SUCCESS_URI);
        Status status = ((SAMLObjectBuilder<Status>) builderFactory.getBuilder(Status.DEFAULT_ELEMENT_NAME)).buildObject();
        status.setStatusCode(statusCode);
        response.setStatus(status);
        response.setIssueInstant(new DateTime());

        Assertion assertion = getValidAssertion();
        assertion.getSubject().getSubjectConfirmations().add(getBearerConfirmation());
        assertion.getAuthnStatements().add(getValidAuthStatement());

        Conditions conditions = (Conditions) ((SAMLObjectBuilder<Status>) builderFactory.getBuilder(Conditions.DEFAULT_ELEMENT_NAME)).buildObject();
        conditions.getAudienceRestrictions().add(getAudienceRestriction("http://localhost:8081/spring-security-saml2-webapp"));
        assertion.setConditions(conditions);

        response.getAssertions().add(assertion);

        return response;
    }

    public SubjectConfirmation getBearerConfirmation() {

        SAMLObjectBuilder<SubjectConfirmation> confirmationBuilder = (SAMLObjectBuilder<SubjectConfirmation>) builderFactory.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
        SubjectConfirmation subjectConfirmation = confirmationBuilder.buildObject();

        SAMLObjectBuilder<SubjectConfirmationData> confirmationDataBuilder = (SAMLObjectBuilder<SubjectConfirmationData>) builderFactory.getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
        SubjectConfirmationData subjectConfirmationData = confirmationDataBuilder.buildObject();

        subjectConfirmationData.setNotOnOrAfter(new DateTime().plusHours(1));

        subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

        subjectConfirmationData.setRecipient("http://www.test.local/SSO");

        return subjectConfirmation;

    }

    public Assertion getValidAssertion() {

        SAMLObjectBuilder<Assertion> assertionBuilder = (SAMLObjectBuilder<Assertion>) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
        Assertion assertion = assertionBuilder.buildObject();
        assertion.setIssueInstant(new DateTime());

        SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue("http://localhost:8080/opensso");
        assertion.setIssuer(issuer);

        SAMLObjectBuilder<Subject> subjectBuilder = (SAMLObjectBuilder<Subject>) builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        Subject subject = subjectBuilder.buildObject();

        SAMLObjectBuilder<NameID> nameIDBuilder = (SAMLObjectBuilder<NameID>) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
        NameID nameID = nameIDBuilder.buildObject();
        nameID.setValue("testUser");
        subject.setNameID(nameID);

        assertion.setSubject(subject);

        return assertion;

    }

    public AttributeStatement getAttributeStatement(String name, String... values) {

        AttributeStatement statement = ((SAMLObjectBuilder<AttributeStatement>) builderFactory.getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME)).buildObject();
        Attribute attribute = ((SAMLObjectBuilder<Attribute>) builderFactory.getBuilder(Attribute.DEFAULT_ELEMENT_NAME)).buildObject();
        attribute.setName(name);

        for (String value : values) {
            XSString stringValue = (XSString) builderFactory.getBuilder(XSString.TYPE_NAME).buildObject(XSString.TYPE_NAME);
            stringValue.setValue(value);
            attribute.getAttributeValues().add(stringValue);
        }

        statement.getAttributes().add(attribute);

        return statement;
    }

    public AuthnStatement getValidAuthStatement() {
        AuthnStatement statement = ((SAMLObjectBuilder<AuthnStatement>) builderFactory.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME)).buildObject();
        DateTime dateNow = new DateTime();
        statement.setAuthnInstant(dateNow);
        DateTime expire = new DateTime().plusHours(3);
        statement.setSessionNotOnOrAfter(expire);
        return statement;
    }

    protected RequestedAuthnContext getRequestedAuthnContext(AuthnContextComparisonTypeEnumeration comparison, Collection<String> contexts) {

        SAMLObjectBuilder<RequestedAuthnContext> builder = (SAMLObjectBuilder<RequestedAuthnContext>) builderFactory.getBuilder(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
        RequestedAuthnContext authnContext = builder.buildObject();
        authnContext.setComparison(comparison);

        for (String context : contexts) {
            authnContext.getAuthnContextClassRefs().add(getClassRef(context));
        }

        return authnContext;

    }

    protected AuthnContextClassRef getClassRef(String context) {
        SAMLObjectBuilder<AuthnContextClassRef> contextRefBuilder = (SAMLObjectBuilder<AuthnContextClassRef>) builderFactory.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        AuthnContextClassRef authnContextClassRef = contextRefBuilder.buildObject();
        authnContextClassRef.setAuthnContextClassRef(context);
        return authnContextClassRef;
    }

    protected AuthnContext getAuthnContext(AuthnContextClassRef classRef, AuthnContextDeclRef declRef) {

        SAMLObjectBuilder<AuthnContext> builder = (SAMLObjectBuilder<AuthnContext>) builderFactory.getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
        AuthnContext authnContext = builder.buildObject();
        authnContext.setAuthnContextClassRef(classRef);
        authnContext.setAuthnContextDeclRef(declRef);
        return authnContext;

    }

    protected AudienceRestriction getAudienceRestriction(String... audienceURI) {
        SAMLObjectBuilder<AudienceRestriction> audienceRestrictionBuilder = (SAMLObjectBuilder<AudienceRestriction>) builderFactory.getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME);
        AudienceRestriction audienceRestriction = audienceRestrictionBuilder.buildObject();
        SAMLObjectBuilder<Audience> audienceBuilder = (SAMLObjectBuilder<Audience>) builderFactory.getBuilder(Audience.DEFAULT_ELEMENT_NAME);
        for (String uri : audienceURI) {
            Audience audience = audienceBuilder.buildObject();
            audience.setAudienceURI(uri);
            audienceRestriction.getAudiences().add(audience);
        }
        return audienceRestriction;
    }

}
