package org.springframework.security.saml.websso;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.*;
import org.opensaml.xml.XMLObjectBuilderFactory;

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

        return response;
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
