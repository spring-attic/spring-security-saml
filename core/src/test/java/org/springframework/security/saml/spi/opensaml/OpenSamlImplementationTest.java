package org.springframework.security.saml.spi.opensaml;

import java.io.IOException;
import java.time.Clock;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.springframework.core.io.ClassPathResource;
import org.springframework.security.saml.saml2.attribute.Attribute;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationContext;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.AuthenticationStatement;
import org.springframework.security.saml.saml2.authentication.Conditions;
import org.springframework.security.saml.saml2.authentication.Issuer;
import org.springframework.security.saml.saml2.authentication.NameIdPrincipal;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.authentication.Scoping;
import org.springframework.security.saml.saml2.authentication.Subject;
import org.springframework.security.saml.saml2.authentication.SubjectConfirmation;
import org.springframework.security.saml.saml2.authentication.SubjectConfirmationData;
import org.springframework.security.saml.saml2.authentication.SubjectConfirmationMethod;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.util.StreamUtils;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.security.saml.util.XmlTestUtil.assertNodeCount;
import static org.springframework.security.saml.util.XmlTestUtil.getNodes;

class OpenSamlImplementationTest {

	private OpenSamlImplementation subject = new OpenSamlImplementation(Clock.systemDefaultZone());

	{
		subject.bootstrap();
	}

	@Test
	public void authenticationRequestWithScopingToXml() {
		AuthenticationRequest authenticationRequest = new AuthenticationRequest();
		String requesterId = "http://requesterId";
		String idpId = "http://idp";
		authenticationRequest
			.setBinding(Binding.REDIRECT)
			.setScoping(new Scoping(
				Collections.singletonList(idpId),
				Collections.singletonList(requesterId),
				new Integer(5)
			))
			.setAssertionConsumerService(endpoint("http://assertionConsumerService"))
			.setDestination(endpoint("http://destination"))
			.setIssuer(new Issuer());

		String xml = subject.toXml(authenticationRequest);

		assertNodeCount(xml, "//saml2p:Scoping", 1);

		Iterable<Node> nodes = getNodes(xml, "//saml2p:Scoping");
		String textContent = nodes.iterator().next().getAttributes().getNamedItem("ProxyCount").getTextContent();
		assertEquals("5", textContent);

		nodes = getNodes(xml, "//saml2p:RequesterID");
		textContent = nodes.iterator().next().getTextContent();
		assertEquals(requesterId, textContent);

		nodes = getNodes(xml, "//saml2p:IDPEntry");
		textContent = nodes.iterator().next().getAttributes().getNamedItem("ProviderID").getTextContent();
		assertEquals(idpId, textContent);
	}

	@Test
	public void resolveAuthnRequestWithScoping() throws IOException {
		Scoping scoping =
			parseScoping("authn_request_with_scoping.xml");

		List<String> idpList = scoping.getIdpList();
		assertEquals(1, idpList.size());
		assertEquals("http://idp", idpList.get(0));

		List<String> requesterIds = scoping.getRequesterIds();
		assertEquals(1, requesterIds.size());
		assertEquals("http://requesterId", requesterIds.get(0));

		assertEquals(5, scoping.getProxyCount().intValue());
	}

	@Test
	public void resolveAuthnRequestWithEmptyScoping() throws IOException {
		Scoping scoping =
			parseScoping("authn_request_with_empty_scoping.xml");

		List<String> idpList = scoping.getIdpList();
		assertEquals(0, idpList.size());

		List<String> requesterIds = scoping.getRequesterIds();
		assertEquals(0, requesterIds.size());

		assertNull(scoping.getProxyCount());
	}

	@Test
	public void resolveAuthnRequestWithNoScoping() throws IOException {
		Scoping scoping =
			parseScoping("authn_request_with_no_scoping.xml");

		assertNull(scoping);
	}

	@Test
	public void assertionWithAuthenticatingAuthoritiesToXml() {
		String authenticatingAuthority = "http://authenticating_authority";
		Assertion assertion = new Assertion()
			.setIssuer(new Issuer())
			.setSubject(new Subject()
				.setPrincipal(new NameIdPrincipal().setValue("admin").setFormat(NameId.UNSPECIFIED))
				.setConfirmations(Arrays.asList(
					new SubjectConfirmation()
						.setMethod(SubjectConfirmationMethod.BEARER)
						.setConfirmationData(new SubjectConfirmationData().setInResponseTo("inResponseTo")))))
			.setAuthenticationStatements(Arrays.asList(
				new AuthenticationStatement()
					.setAuthenticationContext(new AuthenticationContext()
						.setAuthenticatingAuthorities(Arrays.asList(authenticatingAuthority)))))
			.setConditions(new Conditions());

		String xml = subject.toXml(assertion);

		Iterable<Node> nodes = getNodes(xml, "//saml2:AuthenticatingAuthority");
		String textContent = nodes.iterator().next().getTextContent();
		assertEquals(authenticatingAuthority, textContent);
	}

	@Test
	public void resolveAssertionWithAuthenticatinAuthorities() throws IOException {
		AuthenticationContext authenticationContext =
			parseAuthenticationContext("assertion_with_authenticating_authority.xml");
		assertEquals(2, authenticationContext.getAuthenticatingAuthorities().size());
		assertEquals("http://authenticating_authority", authenticationContext.getAuthenticatingAuthorities().get(0));
	}

	@Test
	public void resolveAuthnResponseWithComplexAttributeValue() throws IOException {
		byte[] xml = StreamUtils.copyToByteArray(
			new ClassPathResource("authn_response/authn_response_with_xml_element_attribute_value.xml").getInputStream());
		Response response = (Response) subject.resolve(xml, Collections.emptyList(), Collections.emptyList());
		Assertion assertion = response.getAssertions().get(0);
		Attribute attribute = assertion.getFirstAttribute("urn:mace:dir:attribute-def:eduPersonTargetedID");

		List<Object> values = attribute.getValues();
		assertEquals(1, values.size());

		String value = (String) values.get(0);
		assertEquals("urn:collab:person:example.com:admin", value);
	}

	private Scoping parseScoping(String fileName) throws IOException {
		byte[] xml = StreamUtils.copyToByteArray(
			new ClassPathResource(String.format("authn_requests/%s", fileName)).getInputStream());
		return ((AuthenticationRequest)
			subject.resolve(xml, Collections.emptyList(), Collections.emptyList())).getScoping();
	}

	private AuthenticationContext parseAuthenticationContext(String fileName) throws IOException {
		byte[] xml = StreamUtils.copyToByteArray(
			new ClassPathResource(String.format("assertions/%s", fileName)).getInputStream());
		return ((Assertion)
			subject.resolve(xml, Collections.emptyList(), Collections.emptyList()))
			.getAuthenticationStatements().get(0)
			.getAuthenticationContext();
	}

	private Endpoint endpoint(String location) {
		Endpoint endpoint = new Endpoint();
		endpoint.setLocation(location);
		return endpoint;
	}
}
