/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.springframework.security.saml.saml2.metadata;

import java.io.IOException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import javax.xml.datatype.Duration;

import org.springframework.security.saml.key.KeyType;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.saml2.attribute.Attribute;
import org.springframework.security.saml.saml2.attribute.AttributeNameFormat;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;
import org.springframework.security.saml.saml2.signature.SignatureException;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Node;

import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.saml.saml2.Namespace.NS_PROTOCOL;
import static org.springframework.security.saml.saml2.metadata.Binding.ARTIFACT;
import static org.springframework.security.saml.saml2.metadata.Binding.PAOS;
import static org.springframework.security.saml.saml2.metadata.Binding.POST;
import static org.springframework.security.saml.saml2.metadata.Binding.POST_SIMPLE_SIGN;
import static org.springframework.security.saml.saml2.metadata.Binding.REDIRECT;
import static org.springframework.security.saml.saml2.metadata.Binding.SOAP;
import static org.springframework.security.saml.saml2.metadata.Binding.URI;
import static org.springframework.security.saml.saml2.metadata.NameId.EMAIL;
import static org.springframework.security.saml.saml2.metadata.NameId.PERSISTENT;
import static org.springframework.security.saml.saml2.metadata.NameId.TRANSIENT;
import static org.springframework.security.saml.saml2.metadata.NameId.UNSPECIFIED;
import static org.springframework.security.saml.saml2.metadata.NameId.X509_SUBJECT;
import static org.springframework.security.saml.spi.ExamplePemKey.IDP_RSA_KEY;
import static org.springframework.security.saml.spi.ExamplePemKey.RSA_TEST_KEY;
import static org.springframework.security.saml.util.DateUtils.fromZuluTime;
import static org.springframework.security.saml.util.X509Utilities.keyCleanup;
import static org.springframework.security.saml.util.XmlTestUtil.assertNodeAttribute;
import static org.springframework.security.saml.util.XmlTestUtil.assertNodeCount;

public class MetadataTests extends MetadataBase {

	private SimpleKey keyLoginRunPivotalIo = new SimpleKey(
		"test",
		null,
		"MIIDaDCCAlACCQDFsMECzdtetjANBgkqhkiG9w0BAQUFADB2MQswCQYDVQQGEwJVUzETMBEGA1UE\n" +
			"CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEfMB0GA1UECgwWUGl2b3RhbCBT\n" +
			"b2Z0d2FyZSwgSW5jLjEZMBcGA1UEAwwQKi5ydW4ucGl2b3RhbC5pbzAeFw0xNTA5MDIyMzIwMDla\n" +
			"Fw0xODA5MDEyMzIwMDlaMHYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYD\n" +
			"VQQHDA1TYW4gRnJhbmNpc2NvMR8wHQYDVQQKDBZQaXZvdGFsIFNvZnR3YXJlLCBJbmMuMRkwFwYD\n" +
			"VQQDDBAqLnJ1bi5waXZvdGFsLmlvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyz8C\n" +
			"OS7PJbmziNx1H2tpwSuDSX5ThqasDk/7LZ9FG8s/Zu8IqGQvswoGYx3CWgSaNbVA+Oj9zo7awoao\n" +
			"CLCVfU82O3RxH/gNRJQLwBVlgVys5n9UQ2xmTRMOcCTpR5d/zW4jCBgL4q2hjntgDbQNnQKJExgt\n" +
			"CGZJOQOFzsW3iG5NPfcAj+FPseVfD96I2OG3uxFPmO2Ov/EE7Hid6lETdNkXXEB2SxIebNgr03Dj\n" +
			"l6rFXTTdBXhi9gb+EQSZfbETsOHIDYIMLj0SpJvRcbA+7M4/Vynoxlv+/kICqFjjNATfOrqz7xoU\n" +
			"/VlMn1Z3op3cW8GH3iNHvGfIO7sdy2G0gQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQCq3PQDcIss\n" +
			"cIS1Dq++d1dD4vkGt+8IzYz+ijOLECyXsSm7+b4L+CVinFZ9eF99PLlvvJZ8+zA7NfM1wRpjpdKp\n" +
			"0xLTss8yBDHcZkgwvDrH8aTwUtq8gO67wY3JuWBxjTsnoAPbH8zInkHeolCUSobPxAx9XHqbAxfu\n" +
			"a8HJjDihi+cJYEb5lPSpvY5ytcPG9JAXAHQ6aalpJjkyB+eaGRYi8s5Ejr3luI3nzJEzfUj5y0fc\n" +
			"FTv9CtDt9VfblSuHdRw4uFwat5e1Fb7LtEjATi4cKaG1+zZ80QyuChfC08for83TeQgjq7TA10FA\n" +
			"kKe5nrXyHOORz+ttXkYkp5uEBhpZ",
		null,
		KeyType.SIGNING
	);

	@Test
	public void sp_to_xml() throws Exception {
		ServiceProviderMetadata spm = (ServiceProviderMetadata) config.fromXml(getFileBytes(
			"/test-data/metadata/sp-metadata-with-extras-20180504.xml"), null, null);

		SimpleKey key = spSigning.clone("signing", KeyType.SIGNING);

		spm.getServiceProvider().setKeys(Arrays.asList(key));
		spm.setSigningKey(key, AlgorithmMethod.RSA_SHA512, DigestMethod.SHA512);

		String xml = config.toXml(spm);
		Iterable<Node> nodes = assertNodeCount(xml, "//md:EntityDescriptor", 1);
		assertNodeAttribute(nodes.iterator().next(), "entityID", equalTo("https://sp.saml.spring.io/sp"));

		nodes = assertNodeCount(xml, "//md:SPSSODescriptor", 1);
		assertNodeAttribute(nodes.iterator().next(), "protocolSupportEnumeration", equalTo(NS_PROTOCOL));
		assertNodeAttribute(nodes.iterator().next(), "AuthnRequestsSigned", equalTo("true"));
		assertNodeAttribute(nodes.iterator().next(), "WantAssertionsSigned", equalTo("true"));
		assertNodeAttribute(nodes.iterator().next(), "ID", equalTo("sp.saml.spring.io"));

		assertNodeCount(xml, "//ds:Signature", 1);
		nodes = assertNodeCount(xml, "//ds:Signature/ds:SignedInfo/ds:SignatureMethod", 1);
		assertNodeAttribute(nodes.iterator().next(), "Algorithm", AlgorithmMethod.RSA_SHA512.toString());

		nodes = assertNodeCount(xml, "//ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod", 1);
		assertNodeAttribute(nodes.iterator().next(), "Algorithm", DigestMethod.SHA512.toString());

		assertNodeCount(xml, "//md:SPSSODescriptor/md:Extensions", 1);
		assertNodeCount(xml, "//md:SPSSODescriptor/md:Extensions/idpdisc:DiscoveryResponse", 1);
		assertNodeCount(xml, "//md:SPSSODescriptor/md:Extensions/init:RequestInitiator", 1);

		nodes = assertNodeCount(xml, "//md:KeyDescriptor", 1);
		assertNodeAttribute(nodes.iterator().next(), "use", KeyType.SIGNING.getTypeName());

		nodes = assertNodeCount(xml, "//md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate", 1);
		String textContent = nodes.iterator().next().getTextContent();
		assertNotNull(textContent);
		assertThat(keyCleanup(textContent), equalTo(keyCleanup(key.getCertificate())));

		nodes = assertNodeCount(xml, "//md:ArtifactResolutionService", 1);
		assertNodeAttribute(nodes.iterator().next(), "Binding", equalTo(SOAP.toString()));
		assertNodeAttribute(nodes.iterator().next(), "index", equalTo("0"));
		assertNodeAttribute(
			nodes.iterator().next(),
			"Location",
			equalTo(spm.getServiceProvider().getArtifactResolutionService().get(0).getLocation())
		);

		Iterator<Node> nodeIterator = assertNodeCount(xml, "//md:SingleLogoutService", 4).iterator();
		for (int i = 0; i < 4; i++) {
			Node n = nodeIterator.next();
			assertNodeAttribute(
				n,
				"Location",
				equalTo(spm.getServiceProvider().getSingleLogoutService().get(i).getLocation())
			);
			assertNodeAttribute(
				n,
				"Binding",
				equalTo(spm.getServiceProvider().getSingleLogoutService().get(i).getBinding().toString())
			);
		}

		nodeIterator = assertNodeCount(xml, "//md:NameIDFormat", 4).iterator();
		assertThat(nodeIterator.next().getTextContent(), equalTo(NameId.EMAIL.toString()));
		assertThat(nodeIterator.next().getTextContent(), equalTo(NameId.PERSISTENT.toString()));
		assertThat(nodeIterator.next().getTextContent(), equalTo(NameId.UNSPECIFIED.toString()));
		assertThat(nodeIterator.next().getTextContent(), equalTo("urn:mace:shibboleth:1.0:nameIdentifier"));

		nodeIterator = assertNodeCount(xml, "//md:AssertionConsumerService", 5).iterator();
		for (int i = 0; i < 4; i++) {
			Node n = nodeIterator.next();
			assertNodeAttribute(
				n,
				"Location",
				equalTo(spm.getServiceProvider().getAssertionConsumerService().get(i).getLocation())
			);
			assertNodeAttribute(
				n,
				"Binding",
				equalTo(spm.getServiceProvider().getAssertionConsumerService().get(i).getBinding().toString())
			);
			assertNodeAttribute(n, "index", equalTo("" + i));
			if (i == 0) {
				assertNodeAttribute(n, "isDefault", equalTo("true"));
			}
		}

		nodes = assertNodeCount(xml, "//md:AttributeConsumingService", 1);
		assertNodeAttribute(nodes.iterator().next(), "index", equalTo("0"));
		assertNodeAttribute(nodes.iterator().next(), "isDefault", equalTo("true"));

		nodeIterator = assertNodeCount(xml, "//md:RequestedAttribute", 2).iterator();
		for (int i = 0; i < 2; i++) {
			Node n = nodeIterator.next();
			assertNodeAttribute(
				n,
				"FriendlyName",
				equalTo(spm.getServiceProvider().getRequestedAttributes().get(i).getFriendlyName())
			);
			assertNodeAttribute(n, "Name", equalTo(spm.getServiceProvider().getRequestedAttributes().get(i).getName()));
			assertNodeAttribute(
				n,
				"NameFormat",
				equalTo(spm.getServiceProvider().getRequestedAttributes().get(i).getNameFormat().toString())
			);
			assertNodeAttribute(
				n,
				"isRequired",
				equalTo(spm.getServiceProvider().getRequestedAttributes().get(i).isRequired() + "")
			);
		}

	}

	@Test
	public void idp_to_xml() throws Exception {
		IdentityProviderMetadata ipm = (IdentityProviderMetadata) config.fromXml(getFileBytes(
			"/test-data/metadata/idp-metadata-with-extras-20180507.xml"), null, null);

		SimpleKey key = spSigning.clone("signing", KeyType.SIGNING);

		ipm.getIdentityProvider().setKeys(Arrays.asList(key));
		ipm.setSigningKey(key, AlgorithmMethod.RSA_SHA512, DigestMethod.SHA512);

		String xml = config.toXml(ipm);
		Iterable<Node> nodes = assertNodeCount(xml, "//md:EntityDescriptor", 1);
		assertNodeAttribute(nodes.iterator().next(), "entityID", equalTo("https://idp.saml.spring.io"));

		nodes = assertNodeCount(xml, "//md:IDPSSODescriptor", 1);
		assertNodeAttribute(nodes.iterator().next(), "protocolSupportEnumeration", equalTo(NS_PROTOCOL));
		assertNodeAttribute(nodes.iterator().next(), "WantAuthnRequestsSigned", equalTo("true"));
		assertNodeAttribute(nodes.iterator().next(), "ID", equalTo("idp.saml.spring.io"));

		assertNodeCount(xml, "//ds:Signature", 1);
		nodes = assertNodeCount(xml, "//ds:Signature/ds:SignedInfo/ds:SignatureMethod", 1);
		assertNodeAttribute(nodes.iterator().next(), "Algorithm", AlgorithmMethod.RSA_SHA512.toString());

		nodes = assertNodeCount(xml, "//ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod", 1);
		assertNodeAttribute(nodes.iterator().next(), "Algorithm", DigestMethod.SHA512.toString());

		assertNodeCount(xml, "//md:IDPSSODescriptor/md:Extensions", 1);
		assertNodeCount(xml, "//md:IDPSSODescriptor/md:Extensions/idpdisc:DiscoveryResponse", 1);
		assertNodeCount(xml, "//md:IDPSSODescriptor/md:Extensions/init:RequestInitiator", 1);

		nodes = assertNodeCount(xml, "//md:KeyDescriptor", 1);
		assertNodeAttribute(nodes.iterator().next(), "use", KeyType.SIGNING.getTypeName());

		nodes = assertNodeCount(xml, "//md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate", 1);
		String textContent = nodes.iterator().next().getTextContent();
		assertNotNull(textContent);
		assertThat(keyCleanup(textContent), equalTo(keyCleanup(key.getCertificate())));

		nodes = assertNodeCount(xml, "//md:ArtifactResolutionService", 1);
		assertNodeAttribute(nodes.iterator().next(), "Binding", equalTo(SOAP.toString()));
		assertNodeAttribute(nodes.iterator().next(), "index", equalTo("0"));
		assertNodeAttribute(
			nodes.iterator().next(),
			"Location",
			equalTo(ipm.getIdentityProvider().getArtifactResolutionService().get(0).getLocation())
		);

		Iterator<Node> nodeIterator = assertNodeCount(xml, "//md:SingleLogoutService", 2).iterator();
		for (int i = 0; i < 2; i++) {
			Node n = nodeIterator.next();
			assertNodeAttribute(
				n,
				"Location",
				equalTo(ipm.getIdentityProvider().getSingleLogoutService().get(i).getLocation())
			);
			assertNodeAttribute(
				n,
				"Binding",
				equalTo(ipm.getIdentityProvider().getSingleLogoutService().get(i).getBinding().toString())
			);
		}

		nodeIterator = assertNodeCount(xml, "//md:SingleSignOnService", 4).iterator();
		for (int i = 0; i < 3; i++) {
			Node n = nodeIterator.next();
			assertNodeAttribute(
				n,
				"Location",
				equalTo(ipm.getIdentityProvider().getSingleSignOnService().get(i).getLocation())
			);
			assertNodeAttribute(
				n,
				"Binding",
				equalTo(ipm.getIdentityProvider().getSingleSignOnService().get(i).getBinding().toString())
			);
		}

		nodeIterator = assertNodeCount(xml, "//md:NameIDFormat", 3).iterator();
		assertThat(nodeIterator.next().getTextContent(), equalTo(NameId.TRANSIENT.toString()));
		assertThat(nodeIterator.next().getTextContent(), equalTo(NameId.PERSISTENT.toString()));
		assertThat(nodeIterator.next().getTextContent(), equalTo("urn:mace:shibboleth:1.0:nameIdentifier"));


	}

	@Test
	public void xml_to_sp_external() throws IOException {
		ServiceProviderMetadata sp = (ServiceProviderMetadata) config.fromXml(getFileBytes(
			"/test-data/metadata/sp-metadata-login.run.pivotal.io-20180504.xml"), asList(keyLoginRunPivotalIo), null);
		assertNotNull(sp);
		assertNotNull(sp.getImplementation());
		assertThat(sp.getEntityId(), equalTo("login.run.pivotal.io"));
		assertThat(sp.getEntityAlias(), equalTo("login.run.pivotal.io"));
		assertNotNull(sp.getProviders());
		assertThat(sp.getProviders().size(), equalTo(1));

		ServiceProvider provider = sp.getServiceProvider();
		assertNotNull(provider);
		assertTrue(provider.isWantAssertionsSigned());
		assertTrue(provider.isAuthnRequestsSigned());
		assertThat(provider.getProtocolSupportEnumeration(), containsInAnyOrder(NS_PROTOCOL));

		assertNotNull(provider.getKeys());
		assertThat(provider.getKeys().size(), equalTo(2));
		SimpleKey spSigning = provider.getKeys().get(0);
		SimpleKey spEncryption = provider.getKeys().get(1);
		assertThat(spSigning.getType(), equalTo(KeyType.SIGNING));
		assertThat(spSigning.getCertificate(), equalTo(keyLoginRunPivotalIo.getCertificate()));
		assertThat(spEncryption.getType(), equalTo(KeyType.ENCRYPTION));
		assertThat(spEncryption.getCertificate(), equalTo(keyLoginRunPivotalIo.getCertificate()));

		List<Endpoint> logoutServices = provider.getSingleLogoutService();
		assertNotNull(logoutServices);
		assertThat(logoutServices.size(), equalTo(2));
		Endpoint logout1 = logoutServices.get(0);
		assertNotNull(logout1);
		assertThat(
			logout1.getLocation(),
			equalTo("https://login.run.pivotal.io/saml/SingleLogout/alias/login.run.pivotal.io")
		);
		assertThat(logout1.getBinding(), equalTo(POST));

		Endpoint logout2 = logoutServices.get(1);
		assertNotNull(logout2);
		assertThat(
			logout2.getLocation(),
			equalTo("https://login.run.pivotal.io/saml/SingleLogout/alias/login.run.pivotal.io")
		);
		assertThat(logout2.getBinding(), equalTo(Binding.REDIRECT));

		List<NameId> nameIds = provider.getNameIds();
		assertNotNull(nameIds);
		assertThat(nameIds, containsInAnyOrder(EMAIL, TRANSIENT, PERSISTENT, UNSPECIFIED, X509_SUBJECT));

		List<Endpoint> consumerService = provider.getAssertionConsumerService();
		assertNotNull(consumerService);
		assertThat(consumerService.size(), equalTo(2));

		Endpoint acs1 = consumerService.get(0);
		assertNotNull(acs1);
		assertThat(acs1.getLocation(), equalTo("https://login.run.pivotal.io/saml/SSO/alias/login.run.pivotal.io"));
		assertThat(acs1.getBinding(), equalTo(POST));
		assertThat(acs1.getIndex(), equalTo(0));
		assertThat(acs1.isDefault(), equalTo(true));

		Endpoint acs2 = consumerService.get(1);
		assertNotNull(acs2);
		assertThat(acs2.getLocation(), equalTo("https://login.run.pivotal.io/oauth/token/alias/login.run.pivotal.io"));
		assertThat(acs2.getBinding(), equalTo(URI));
		assertThat(acs2.getIndex(), equalTo(1));
		assertThat(acs2.isDefault(), equalTo(false));

	}

	@Test
	public void xml_to_sp_complete() throws IOException {
		ServiceProviderMetadata sp = (ServiceProviderMetadata) config.fromXml(getFileBytes(
			"/test-data/metadata/sp-metadata-with-extras-20180504.xml"), null, null);
		assertNotNull(sp);
		assertNotNull(sp.getImplementation());
		assertThat(sp.getEntityId(), equalTo("https://sp.saml.spring.io/sp"));
		assertThat(sp.getEntityAlias(), equalTo(sp.getEntityId()));
		assertNotNull(sp.getProviders());
		assertThat(sp.getProviders().size(), equalTo(1));

		ServiceProvider provider = sp.getServiceProvider();
		assertNotNull(provider);
		assertTrue(provider.isWantAssertionsSigned());
		assertTrue(provider.isAuthnRequestsSigned());
		assertThat(provider.getProtocolSupportEnumeration(), containsInAnyOrder(NS_PROTOCOL));
		assertThat(provider.getId(), equalTo("sp.saml.spring.io"));
		Duration cacheDuration = provider.getCacheDuration();
		assertNotNull(cacheDuration);
		assertThat(cacheDuration.getYears(), equalTo(2));
		assertThat(cacheDuration.getMonths(), equalTo(6));
		assertThat(cacheDuration.getDays(), equalTo(5));
		assertThat(cacheDuration.getHours(), equalTo(12));
		assertThat(cacheDuration.getMinutes(), equalTo(35));
		assertThat(cacheDuration.getSeconds(), equalTo(30));
		assertThat(provider.getValidUntil(), equalTo(fromZuluTime("2028-05-02T20:07:06.785Z")));

		Endpoint requestInitiation = provider.getRequestInitiation();
		assertNotNull(requestInitiation);
		assertThat(requestInitiation.isDefault(), equalTo(false));
		assertThat(requestInitiation.getBinding(), equalTo(Binding.REQUEST_INITIATOR));
		assertThat(requestInitiation.getIndex(), equalTo(0));
		assertThat(requestInitiation.getLocation(), equalTo("https://sp.saml.spring.io/saml/sp/init"));

		Endpoint discovery = provider.getDiscovery();
		assertNotNull(discovery);
		assertThat(discovery.isDefault(), equalTo(true));
		assertThat(discovery.getBinding(), equalTo(Binding.DISCOVERY));
		assertThat(discovery.getIndex(), equalTo(0));
		assertThat(discovery.getLocation(), equalTo("https://sp.saml.spring.io/saml/sp/discovery"));

		assertNotNull(provider.getKeys());
		assertThat(provider.getKeys().size(), equalTo(1));
		SimpleKey spSigning = provider.getKeys().get(0);
		assertThat(spSigning.getType(), equalTo(KeyType.SIGNING));
		assertThat(spSigning.getCertificate(), equalTo(RSA_TEST_KEY.getSimpleKey("test").getCertificate()));


		List<Endpoint> logoutServices = provider.getSingleLogoutService();
		assertNotNull(logoutServices);
		assertThat(logoutServices.size(), equalTo(4));
		for (int i = 0; i < logoutServices.size(); i++) {
			Endpoint logout = logoutServices.get(i);
			assertNotNull(logout);
			assertThat(logout.getLocation(), equalTo("https://sp.saml.spring.io/saml/sp/logout"));
			Binding b = null;
			switch (i) {
				case 0:
					b = SOAP;
					break;
				case 1:
					b = REDIRECT;
					break;
				case 2:
					b = POST;
					break;
				case 3:
					b = ARTIFACT;
					break;
			}
			assertThat(logout.getBinding(), equalTo(b));
		}


		List<NameId> nameIds = provider.getNameIds();
		assertNotNull(nameIds);
		assertThat(nameIds, containsInAnyOrder(EMAIL, PERSISTENT, UNSPECIFIED, NameId.fromUrn("urn:mace:shibboleth:1.0:nameIdentifier")));

		List<Endpoint> consumerService = provider.getAssertionConsumerService();
		assertNotNull(consumerService);
		assertThat(consumerService.size(), equalTo(5));

		Endpoint acs1 = consumerService.get(0);
		assertNotNull(acs1);
		assertThat(acs1.getLocation(), equalTo("https://sp.saml.spring.io/saml/sp/sso"));
		assertThat(acs1.getBinding(), equalTo(POST));
		assertThat(acs1.getIndex(), equalTo(0));
		assertThat(acs1.isDefault(), equalTo(true));

		Endpoint acs2 = consumerService.get(1);
		assertNotNull(acs2);
		assertThat(acs2.getLocation(), equalTo("https://sp.saml.spring.io/saml/sp/sso/simple"));
		assertThat(acs2.getBinding(), equalTo(POST_SIMPLE_SIGN));
		assertThat(acs2.getIndex(), equalTo(1));
		assertThat(acs2.isDefault(), equalTo(false));

		Endpoint acs3 = consumerService.get(2);
		assertNotNull(acs3);
		assertThat(acs3.getLocation(), equalTo("https://sp.saml.spring.io/saml/sp/sso/artifact"));
		assertThat(acs3.getBinding(), equalTo(ARTIFACT));
		assertThat(acs3.getIndex(), equalTo(2));
		assertThat(acs3.isDefault(), equalTo(false));

		Endpoint acs4 = consumerService.get(3);
		assertNotNull(acs4);
		assertThat(acs4.getLocation(), equalTo("https://sp.saml.spring.io/saml/sp/sso/ecp"));
		assertThat(acs4.getBinding(), equalTo(PAOS));
		assertThat(acs4.getIndex(), equalTo(3));
		assertThat(acs4.isDefault(), equalTo(false));

		Endpoint acs5 = consumerService.get(4);
		assertNotNull(acs5);
		assertThat(acs5.getLocation(), equalTo("https://sp.saml.spring.io/saml/sp/sso/assertion"));
		assertThat(acs5.getBinding(), equalTo(Binding.fromUrn("urn:mace:shibboleth:2.0:profiles:Assertion")));
		assertThat(acs5.getIndex(), equalTo(4));
		assertThat(acs5.isDefault(), equalTo(false));

		List<Attribute> attributes = provider.getRequestedAttributes();
		assertNotNull(attributes);

		assertThat(attributes.size(), equalTo(2));

		Attribute a1 = attributes.get(0);
		assertNotNull(a1);
		assertThat(a1.getFriendlyName(), equalTo("mail"));
		assertThat(a1.getName(), equalTo("urn:oid:0.9.2342.19200300.100.1.3"));
		assertThat(a1.getNameFormat(), equalTo(AttributeNameFormat.URI));
		assertThat(a1.isRequired(), equalTo(true));

		Attribute a2 = attributes.get(1);
		assertNotNull(a2);
		assertThat(a2.getFriendlyName(), equalTo("eppn"));
		assertThat(a2.getName(), equalTo("urn:oid:1.3.6.1.4.1.5923.1.1.1.6"));
		assertThat(a2.getNameFormat(), equalTo(AttributeNameFormat.BASIC));
		assertThat(a2.isRequired(), equalTo(false));


	}

	@Test
	public void sp_invalid_verification_key() {
		assertThrows(
			SignatureException.class,
			() -> config.fromXml(
				getFileBytes("/test-data/metadata/sp-metadata-login.run.pivotal.io-20180504.xml"),
				asList(RSA_TEST_KEY.getSimpleKey("alias")),
				null
			)
		);
	}

	@Test
	public void xml_to_idp_complete() throws Exception {
		IdentityProviderMetadata idp = (IdentityProviderMetadata) config.fromXml(getFileBytes(
			"/test-data/metadata/idp-metadata-with-extras-20180507.xml"), null, null);
		assertNotNull(idp);
		assertNotNull(idp.getImplementation());
		assertThat(idp.getEntityId(), equalTo("https://idp.saml.spring.io"));
		assertThat(idp.getEntityAlias(), equalTo(idp.getEntityId()));
		assertNotNull(idp.getProviders());
		assertThat(idp.getProviders().size(), equalTo(1));

		IdentityProvider provider = idp.getIdentityProvider();
		assertNotNull(provider);
		assertTrue(provider.getWantAuthnRequestsSigned());
		assertThat(provider.getProtocolSupportEnumeration(), containsInAnyOrder(NS_PROTOCOL));
		assertThat(provider.getId(), equalTo("idp.saml.spring.io"));
		Duration cacheDuration = provider.getCacheDuration();
		assertNotNull(cacheDuration);
		assertThat(cacheDuration.getYears(), equalTo(2));
		assertThat(cacheDuration.getMonths(), equalTo(6));
		assertThat(cacheDuration.getDays(), equalTo(5));
		assertThat(cacheDuration.getHours(), equalTo(12));
		assertThat(cacheDuration.getMinutes(), equalTo(35));
		assertThat(cacheDuration.getSeconds(), equalTo(30));
		assertThat(provider.getValidUntil(), equalTo(fromZuluTime("2028-05-02T20:07:06.785Z")));

		Endpoint requestInitiation = provider.getRequestInitiation();
		assertNotNull(requestInitiation);
		assertThat(requestInitiation.isDefault(), equalTo(false));
		assertThat(requestInitiation.getBinding(), equalTo(Binding.REQUEST_INITIATOR));
		assertThat(requestInitiation.getIndex(), equalTo(0));
		assertThat(requestInitiation.getLocation(), equalTo("https://idp.saml.spring.io/saml/idp/init"));

		Endpoint discovery = provider.getDiscovery();
		assertNotNull(discovery);
		assertThat(discovery.isDefault(), equalTo(true));
		assertThat(discovery.getBinding(), equalTo(Binding.DISCOVERY));
		assertThat(discovery.getIndex(), equalTo(0));
		assertThat(discovery.getLocation(), equalTo("https://idp.saml.spring.io/saml/idp/discovery"));

		assertNotNull(provider.getKeys());
		assertThat(provider.getKeys().size(), equalTo(2));
		SimpleKey spSigning = provider.getKeys().get(0);
		SimpleKey spEncryption = provider.getKeys().get(1);
		assertThat(spSigning.getType(), equalTo(KeyType.SIGNING));
		assertThat(spSigning.getCertificate(), equalTo(IDP_RSA_KEY.getSimpleKey("alias").getCertificate()));
		assertThat(spEncryption.getType(), equalTo(KeyType.ENCRYPTION));
		assertThat(spEncryption.getCertificate(), equalTo(IDP_RSA_KEY.getSimpleKey("alias").getCertificate()));

		List<NameId> nameIds = provider.getNameIds();
		assertNotNull(nameIds);
		assertThat(nameIds, containsInAnyOrder(TRANSIENT, PERSISTENT, NameId.fromUrn("urn:mace:shibboleth:1.0:nameIdentifier")));

		List<Endpoint> singleSignOnServices = provider.getSingleSignOnService();
		assertNotNull(singleSignOnServices);
		assertThat(singleSignOnServices.size(), equalTo(4));
		Endpoint sso0 = singleSignOnServices.get(0);
		assertNotNull(sso0);
		assertThat(sso0.getLocation(), equalTo("https://idp.saml.spring.io/saml/idp/sso"));
		assertThat(sso0.getBinding(), equalTo(POST));

		Endpoint sso1 = singleSignOnServices.get(1);
		assertNotNull(sso1);
		assertThat(sso1.getLocation(), equalTo("https://idp.saml.spring.io/saml/idp/sso"));
		assertThat(sso1.getBinding(), equalTo(POST_SIMPLE_SIGN));

		Endpoint sso2 = singleSignOnServices.get(2);
		assertNotNull(sso2);
		assertThat(sso2.getLocation(), equalTo("https://idp.saml.spring.io/saml/idp/sso"));
		assertThat(sso2.getBinding(), equalTo(REDIRECT));

		Endpoint sso3 = singleSignOnServices.get(3);
		assertNotNull(sso3);
		assertThat(sso3.getLocation(), equalTo("https://shibbolethidp/idp/profile/SAML2/Unsolicited/SSO"));
		assertThat(sso3.getBinding(), equalTo(Binding.fromUrn("urn:mace:shibboleth:2.0:profiles:AuthnRequest")));
	}

	@Test
	public void xml_to_idp_external() throws Exception {
		IdentityProviderMetadata idp = (IdentityProviderMetadata) config.fromXml(getFileBytes(
			"/test-data/metadata/idp-metadata-login.run.pivotal.io-20180504.xml"), asList(keyLoginRunPivotalIo), null);
		assertNotNull(idp);
		assertNotNull(idp.getImplementation());
		assertThat(idp.getEntityId(), equalTo("login.run.pivotal.io"));
		assertThat(idp.getEntityAlias(), equalTo("login.run.pivotal.io"));
		assertNotNull(idp.getProviders());
		assertThat(idp.getProviders().size(), equalTo(1));

		IdentityProvider provider = idp.getIdentityProvider();
		assertNotNull(provider);
		assertFalse(provider.getWantAuthnRequestsSigned());
		assertThat(provider.getProtocolSupportEnumeration(), containsInAnyOrder(NS_PROTOCOL));

		assertNotNull(provider.getKeys());
		assertThat(provider.getKeys().size(), equalTo(2));
		SimpleKey spSigning = provider.getKeys().get(0);
		SimpleKey spEncryption = provider.getKeys().get(1);
		assertThat(spSigning.getType(), equalTo(KeyType.SIGNING));
		assertThat(spSigning.getCertificate(), equalTo(keyLoginRunPivotalIo.getCertificate()));
		assertThat(spEncryption.getType(), equalTo(KeyType.ENCRYPTION));
		assertThat(spEncryption.getCertificate(), equalTo(keyLoginRunPivotalIo.getCertificate()));

		List<NameId> nameIds = provider.getNameIds();
		assertNotNull(nameIds);
		assertThat(nameIds, containsInAnyOrder(EMAIL, PERSISTENT, UNSPECIFIED));

		List<Endpoint> singleSignOnServices = provider.getSingleSignOnService();
		assertNotNull(singleSignOnServices);
		assertThat(singleSignOnServices.size(), equalTo(2));
		Endpoint sso1 = singleSignOnServices.get(0);
		assertNotNull(sso1);
		assertThat(sso1.getLocation(), equalTo("https://login.run.pivotal.io/saml/idp/SSO/alias/login.run.pivotal.io"));
		assertThat(sso1.getBinding(), equalTo(POST));

		Endpoint sso2 = singleSignOnServices.get(1);
		assertNotNull(sso2);
		assertThat(sso2.getLocation(), equalTo("https://login.run.pivotal.io/saml/idp/SSO/alias/login.run.pivotal.io"));
		assertThat(sso2.getBinding(), equalTo(REDIRECT));
	}

	@Test
	public void idp_invalid_verification_key() {
		assertThrows(
			SignatureException.class,
			() -> config.fromXml(
				getFileBytes("/test-data/metadata/idp-metadata-login.run.pivotal.io-20180504.xml"),
				asList(RSA_TEST_KEY.getSimpleKey("alias")),
				null
			)
		);
	}

	@Test
	public void entities_descriptor() throws IOException {
		Metadata entities =
			(Metadata) config.fromXml(
				getFileBytes("/test-data/metadata/entities-descriptor-example.xml"),
				asList(), //no verification here yet
				null
			);
		assertNotNull(entities);
		assertThat(entities.getClass(), equalTo(IdentityProviderMetadata.class));
		assertTrue(entities.hasNext());
		assertThat(entities.getNext().getClass(), equalTo(ServiceProviderMetadata.class));
	}

	@Test
	public void multiple_descriptors() throws IOException {
		Metadata entities =
			(Metadata) config.fromXml(
				getFileBytes("/test-data/metadata/multi-descriptor-metadata.xml"),
				asList(), //no verification here yet
				null
			);
		assertNotNull(entities);
		assertThat(entities.getClass(), equalTo(Metadata.class));
		assertFalse(entities.hasNext());
	}


}
