package org.springframework.security.saml.websso;

import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.Configuration;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.joda.time.DateTime;

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

}
