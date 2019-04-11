/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.saml2.spi.keycloak;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.Duration;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.Saml2KeyException;
import org.springframework.security.saml2.model.Saml2ImplementationHolder;
import org.springframework.security.saml2.model.Saml2Object;
import org.springframework.security.saml2.model.Saml2SignableObject;
import org.springframework.security.saml2.model.attribute.Saml2Attribute;
import org.springframework.security.saml2.model.attribute.Saml2AttributeNameFormat;
import org.springframework.security.saml2.model.authentication.Saml2Assertion;
import org.springframework.security.saml2.model.authentication.Saml2AssertionCondition;
import org.springframework.security.saml2.model.authentication.Saml2AudienceRestriction;
import org.springframework.security.saml2.model.authentication.Saml2AuthenticationContext;
import org.springframework.security.saml2.model.authentication.Saml2AuthenticationContextClassReference;
import org.springframework.security.saml2.model.authentication.Saml2AuthenticationRequest;
import org.springframework.security.saml2.model.authentication.Saml2AuthenticationStatement;
import org.springframework.security.saml2.model.authentication.Saml2Conditions;
import org.springframework.security.saml2.model.authentication.Saml2Issuer;
import org.springframework.security.saml2.model.authentication.Saml2LogoutReason;
import org.springframework.security.saml2.model.authentication.Saml2LogoutSaml2Request;
import org.springframework.security.saml2.model.authentication.Saml2LogoutResponse;
import org.springframework.security.saml2.model.authentication.Saml2NameIdPolicy;
import org.springframework.security.saml2.model.authentication.Saml2NameIdPrincipalSaml2;
import org.springframework.security.saml2.model.authentication.Saml2OneTimeUse;
import org.springframework.security.saml2.model.authentication.Saml2RequestedAuthenticationContext;
import org.springframework.security.saml2.model.authentication.Saml2ResponseSaml2;
import org.springframework.security.saml2.model.authentication.Saml2Status;
import org.springframework.security.saml2.model.authentication.Saml2StatusCode;
import org.springframework.security.saml2.model.authentication.Saml2Subject;
import org.springframework.security.saml2.model.authentication.Saml2SubjectConfirmation;
import org.springframework.security.saml2.model.authentication.Saml2SubjectConfirmationData;
import org.springframework.security.saml2.model.authentication.Saml2SubjectConfirmationMethod;
import org.springframework.security.saml2.model.key.Saml2KeyData;
import org.springframework.security.saml2.model.key.Saml2KeyType;
import org.springframework.security.saml2.model.metadata.Saml2Binding;
import org.springframework.security.saml2.model.metadata.Saml2Endpoint;
import org.springframework.security.saml2.model.metadata.Saml2IdentityProvider;
import org.springframework.security.saml2.model.metadata.Saml2IdentityProviderMetadata;
import org.springframework.security.saml2.model.metadata.Saml2Metadata;
import org.springframework.security.saml2.model.metadata.Saml2NameId;
import org.springframework.security.saml2.model.metadata.Saml2Provider;
import org.springframework.security.saml2.model.metadata.Saml2ServiceProvider;
import org.springframework.security.saml2.model.metadata.Saml2ServiceProviderMetadata;
import org.springframework.security.saml2.model.metadata.Saml2SsoProvider;
import org.springframework.security.saml2.model.signature.Saml2Signature;
import org.springframework.security.saml2.model.signature.Saml2SignatureException;
import org.springframework.security.saml2.Saml2KeyStoreProvider;
import org.springframework.security.saml2.spi.SpringSecuritySaml2;
import org.springframework.security.saml2.util.Saml2DateUtils;
import org.springframework.security.saml2.util.Saml2X509Utils;
import org.springframework.util.CollectionUtils;
import org.springframework.util.ReflectionUtils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.dom.saml.v2.assertion.AudienceRestrictionType;
import org.keycloak.dom.saml.v2.assertion.AuthnContextClassRefType;
import org.keycloak.dom.saml.v2.assertion.AuthnContextType;
import org.keycloak.dom.saml.v2.assertion.AuthnStatementType;
import org.keycloak.dom.saml.v2.assertion.ConditionAbstractType;
import org.keycloak.dom.saml.v2.assertion.ConditionsType;
import org.keycloak.dom.saml.v2.assertion.EncryptedAssertionType;
import org.keycloak.dom.saml.v2.assertion.EncryptedElementType;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.assertion.OneTimeUseType;
import org.keycloak.dom.saml.v2.assertion.StatementAbstractType;
import org.keycloak.dom.saml.v2.assertion.SubjectConfirmationDataType;
import org.keycloak.dom.saml.v2.assertion.SubjectConfirmationType;
import org.keycloak.dom.saml.v2.assertion.SubjectType;
import org.keycloak.dom.saml.v2.metadata.AttributeConsumingServiceType;
import org.keycloak.dom.saml.v2.metadata.EndpointType;
import org.keycloak.dom.saml.v2.metadata.EntitiesDescriptorType;
import org.keycloak.dom.saml.v2.metadata.EntityDescriptorType;
import org.keycloak.dom.saml.v2.metadata.ExtensionsType;
import org.keycloak.dom.saml.v2.metadata.IDPSSODescriptorType;
import org.keycloak.dom.saml.v2.metadata.IndexedEndpointType;
import org.keycloak.dom.saml.v2.metadata.KeyDescriptorType;
import org.keycloak.dom.saml.v2.metadata.KeyTypes;
import org.keycloak.dom.saml.v2.metadata.RequestedAttributeType;
import org.keycloak.dom.saml.v2.metadata.RoleDescriptorType;
import org.keycloak.dom.saml.v2.metadata.SPSSODescriptorType;
import org.keycloak.dom.saml.v2.metadata.SSODescriptorType;
import org.keycloak.dom.saml.v2.protocol.AuthnContextComparisonType;
import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.dom.saml.v2.protocol.LogoutRequestType;
import org.keycloak.dom.saml.v2.protocol.NameIDPolicyType;
import org.keycloak.dom.saml.v2.protocol.RequestedAuthnContextType;
import org.keycloak.dom.saml.v2.protocol.ResponseType;
import org.keycloak.dom.saml.v2.protocol.StatusCodeType;
import org.keycloak.dom.saml.v2.protocol.StatusResponseType;
import org.keycloak.dom.saml.v2.protocol.StatusType;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.saml.common.util.StaxUtil;
import org.keycloak.saml.processing.core.parsers.saml.assertion.SAMLAttributeValueParser;
import org.keycloak.saml.processing.core.saml.v2.writers.SAMLAssertionWriter;
import org.keycloak.saml.processing.core.saml.v2.writers.SAMLMetadataWriter;
import org.keycloak.saml.processing.core.saml.v2.writers.SAMLRequestWriter;
import org.keycloak.saml.processing.core.saml.v2.writers.SAMLResponseWriter;
import org.keycloak.saml.processing.core.util.JAXPValidationUtil;
import org.keycloak.saml.processing.core.util.XMLEncryptionUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static java.util.Collections.emptyList;
import static java.util.Optional.ofNullable;
import static org.keycloak.saml.processing.api.saml.v2.sig.SAML2Signature.configureIdAttribute;
import static org.springframework.security.saml2.model.Saml2Namespace.NS_SIGNATURE;
import static org.springframework.security.saml2.util.Saml2DateUtils.toDateTime;
import static org.springframework.security.saml2.util.Saml2DateUtils.toZuluTime;
import static org.springframework.security.saml2.util.Saml2StringUtils.getHostFromUrl;
import static org.springframework.security.saml2.util.Saml2StringUtils.isUrl;
import static org.springframework.util.StringUtils.hasText;

public class KeycloakSaml2Implementation extends SpringSecuritySaml2<KeycloakSaml2Implementation> {

	private static final Log logger = LogFactory.getLog(KeycloakSaml2Implementation.class);
	private Saml2KeyStoreProvider samlKeyStoreProvider = new Saml2KeyStoreProvider() {};
	private KeycloakSaml2Parser samlParser = new KeycloakSaml2Parser();

	public KeycloakSaml2Implementation(Clock time) {
		super(time);
	}

	private Saml2Metadata determineMetadataType(List<? extends Saml2Provider> ssoProviders) {
		Saml2Metadata result = new Saml2Metadata();
		long sps = ssoProviders.stream().filter(p -> p instanceof Saml2ServiceProvider).count();
		long idps = ssoProviders.stream().filter(p -> p instanceof Saml2IdentityProvider).count();

		if (ssoProviders.size() == sps) {
			result = new Saml2ServiceProviderMetadata();
		}
		else if (ssoProviders.size() == idps) {
			result = new Saml2IdentityProviderMetadata();
		}
		result.setProviders(ssoProviders);
		return result;
	}


	private Saml2KeyStoreProvider getSamlKeyStoreProvider() {
		return samlKeyStoreProvider;
	}

	public KeycloakSaml2Implementation setSamlKeyStoreProvider(Saml2KeyStoreProvider samlKeyStoreProvider) {
		this.samlKeyStoreProvider = samlKeyStoreProvider;
		return this;
	}

	protected void bootstrap() {
		try {
			overrideSingletonField(SAMLAttributeValueParser.class, "INSTANCE", new KeycloakSaml2AttributeParser());
		} catch (NoSuchFieldException | IllegalAccessException e) {
			throw new Saml2Exception("Unable to initialize attribute parser to support xsd:DateTime formats", e);
		}
		org.apache.xml.security.Init.init();
	}

	private void overrideSingletonField(Class<?> clazz, String name, KeycloakSaml2AttributeParser value)
		throws NoSuchFieldException, IllegalAccessException {
		Field instance = ReflectionUtils.findField(clazz, name);
		instance.setAccessible(true);
		Field modifiersField = Field.class.getDeclaredField("modifiers");
		modifiersField.setAccessible(true);
		modifiersField.setInt(instance, instance.getModifiers() & ~Modifier.FINAL);
		instance.set(null, value);
	}

	@Override
	protected Duration toDuration(long millis) {
		try {
			return DatatypeFactory.newInstance().newDuration(millis);
		} catch (DatatypeConfigurationException e) {
			throw new Saml2Exception(e);
		}
	}

	@Override
	protected String toXml(Saml2Object saml2Object) {
		Object result = null;
		if (saml2Object instanceof Saml2Metadata) {
			result = internalToXml((Saml2Metadata) saml2Object);
		}
		else if (saml2Object instanceof Saml2AuthenticationRequest) {
			result = internalToXml((Saml2AuthenticationRequest) saml2Object);
		}
		else if (saml2Object instanceof Saml2Assertion) {
			result = internalToXml((Saml2Assertion) saml2Object);
		}
		else if (saml2Object instanceof Saml2ResponseSaml2) {
			result = internalToXml((Saml2ResponseSaml2) saml2Object);
		}
		else if (saml2Object instanceof Saml2LogoutSaml2Request) {
			result = internalToXml((Saml2LogoutSaml2Request) saml2Object);
		}
		else if (saml2Object instanceof Saml2LogoutResponse) {
			result = internalToXml((Saml2LogoutResponse) saml2Object);
		}
		if (result == null) {
			throw new Saml2Exception("To xml transformation not supported for: " +
				saml2Object != null ?
				saml2Object.getClass().getName() :
				"null"
			);
		}
		String xml = marshallToXml(result);
		if (saml2Object instanceof Saml2SignableObject) {
			Saml2SignableObject signable = (Saml2SignableObject) saml2Object;
			xml = signObject(xml, signable);
		}
		return xml;
	}

	@Override
	protected Saml2Object resolve(byte[] xml, List<Saml2KeyData> verificationKeys, List<Saml2KeyData> localKeys) {
		Saml2ObjectHolder parsed = parse(xml);
		Map<String, Saml2Signature> signatureMap = KeycloakSaml2SignatureValidator.validateSignature(parsed, verificationKeys);
		Saml2Object result = null;
		if (parsed.getSaml2Object() instanceof EntityDescriptorType) {
			result = resolveMetadata(
				(EntityDescriptorType) parsed.getSaml2Object(),
				signatureMap
			);
		}
		else if (parsed.getSaml2Object() instanceof EntitiesDescriptorType) {
			result =
				resolveMetadata(
					(EntitiesDescriptorType) parsed.getSaml2Object(),
					signatureMap
				);
			;
		}
		else if (parsed.getSaml2Object() instanceof AuthnRequestType) {
			result = resolveAuthenticationRequest(
				(AuthnRequestType) parsed.getSaml2Object(),
				signatureMap
			);
		}
		else if (parsed.getSaml2Object() instanceof ResponseType) {
			result = resolveResponse(
				(ResponseType) parsed.getSaml2Object(),
				signatureMap,
				localKeys
			);
		}
		else if (parsed.getSaml2Object() instanceof AssertionType) {
			AssertionType at = (AssertionType) parsed.getSaml2Object();
			result = resolveAssertion(
				at,
				signatureMap,
				localKeys,
				false
			);
		}
		else if (parsed.getSaml2Object() instanceof LogoutRequestType) {
			result = resolveLogoutRequest(
				(LogoutRequestType) parsed.getSaml2Object(),
				signatureMap,
				localKeys);
		}
		else if (parsed.getSaml2Object() instanceof StatusResponseType) {
			result = resolveLogoutResponse(
				(StatusResponseType) parsed.getSaml2Object(),
				signatureMap,
				localKeys
			);
		}
		if (result != null) {
			if (result instanceof Saml2ImplementationHolder) {
				((Saml2ImplementationHolder) result).setImplementation(parsed);
				((Saml2ImplementationHolder) result).setOriginalDataRepresentation(new String(xml, StandardCharsets.UTF_8));
			}
			return result;
		}
		throw new Saml2Exception("Deserialization not yet supported for class: " + parsed.getSaml2Object().getClass());
	}

	@Override
	protected Saml2Signature getValidSignature(Saml2SignableObject saml2Object, List<Saml2KeyData> trustedKeys) {
		if (saml2Object.getImplementation() instanceof Saml2ObjectHolder) {
			Map<String, Saml2Signature> signatureMap =
				KeycloakSaml2SignatureValidator.validateSignature(
					(Saml2ObjectHolder) saml2Object.getImplementation(),
					trustedKeys
				);

			if (saml2Object instanceof Saml2ResponseSaml2) {
				Saml2ResponseSaml2 r = (Saml2ResponseSaml2)saml2Object;
				for (Saml2Assertion assertion : r.getAssertions()) {
					if (assertion.getImplementation() != null &&
						assertion.getSignature() == null) {
						AssertionType t = (AssertionType) assertion.getImplementation();
						KeycloakSaml2SignatureValidator.assignSignatureToObject(
							signatureMap,
							assertion,
							t.getSignature()
						);
					}
				}
				ResponseType rt = (ResponseType) ((Saml2ObjectHolder) saml2Object.getImplementation()).getSaml2Object();
				if (rt.getSignature() != null) {
					KeycloakSaml2SignatureValidator.assignSignatureToObject(
						signatureMap,
						saml2Object,
						rt.getSignature()
					);
				}
				return r.getSignature();
			}

			if (!signatureMap.isEmpty()) {
				return signatureMap.entrySet().iterator().next().getValue();
			}
			else {
				return null;
			}
		}
		else {
			throw new Saml2SignatureException(
				"Unrecognized object type:" + saml2Object.getImplementation().getClass().getName()
			);
		}
	}

	private EntityDescriptorType internalToXml(Saml2Metadata<? extends Saml2Metadata> metadata) {
		EntityDescriptorType desc = new EntityDescriptorType(metadata.getEntityId());
		if (!hasText(metadata.getId())) {
			metadata.setId("M" + UUID.randomUUID().toString());
		}
		desc.setID(metadata.getId());
		List<RoleDescriptorType> descriptors = getRoleDescriptors(metadata);
		descriptors.stream().forEach(
			d -> {
				if (d instanceof SSODescriptorType) {
					desc.addChoiceType(
						EntityDescriptorType.EDTChoiceType.oneValue(
							new EntityDescriptorType.EDTDescriptorChoiceType((SSODescriptorType) d)
						)
					);
				}
			}
		);
		return desc;
	}

	private AuthnRequestType internalToXml(Saml2AuthenticationRequest request) {
		XMLGregorianCalendar instant =
			getXmlGregorianCalendar(ofNullable(request.getIssueInstant()).orElse(DateTime.now()));
		if (!hasText(request.getId())) {
			request.setId("AN" + UUID.randomUUID().toString());
		}
		AuthnRequestType auth = new AuthnRequestType(request.getId(), instant);
		auth.setForceAuthn(request.isForceAuth());
		auth.setIsPassive(request.isPassive());
		try {
			auth.setProtocolBinding(request.getBinding().getValue());
			auth.setAssertionConsumerServiceURL(new URI(request.getAssertionConsumerService().getLocation()));
			auth.setDestination(new URI(request.getDestination().getLocation()));
		} catch (URISyntaxException e) {
			throw new Saml2Exception(e);
		}
		// Azure AD as IdP will not accept index if protocol binding or AssertationCustomerServiceURL is set.
		//auth.setAssertionConsumerServiceIndex(request.getAssertionConsumerService().getIndex());
		auth.setNameIDPolicy(getNameIDPolicy(request.getNameIdPolicy()));
		auth.setRequestedAuthnContext(getRequestedAuthenticationContext(request));
		auth.setIssuer(toIssuer(request.getIssuer()));
		return auth;
	}

	private String marshallToXml(Object object) {
		StringWriter writer = new StringWriter();
		if (object instanceof EntityDescriptorType) {
			try {
				XMLStreamWriter streamWriter = StaxUtil.getXMLStreamWriter(writer);
				SAMLMetadataWriter metadataWriter = new KeycloakSaml2MetadataWriter(streamWriter);
				metadataWriter.writeEntityDescriptor((EntityDescriptorType) object);
				streamWriter.flush();
				return writer.getBuffer().toString();
			} catch (ProcessingException | XMLStreamException e) {
				throw new Saml2Exception(e);
			}
		}
		else if (object instanceof AuthnRequestType) {
			try {
				XMLStreamWriter streamWriter = StaxUtil.getXMLStreamWriter(writer);
				SAMLRequestWriter requestWriter = new SAMLRequestWriter(streamWriter);
				requestWriter.write((AuthnRequestType) object);
				streamWriter.flush();
				return writer.getBuffer().toString();
			} catch (ProcessingException | XMLStreamException e) {
				throw new Saml2Exception(e);
			}
		}
		else if (object instanceof AssertionType) {
			try {
				XMLStreamWriter streamWriter = StaxUtil.getXMLStreamWriter(writer);
				SAMLAssertionWriter assertionWriter = new KeycloakSaml2AssertionWriter(streamWriter);
				assertionWriter.write((AssertionType) object);
				streamWriter.flush();
				return writer.getBuffer().toString();
			} catch (ProcessingException | XMLStreamException e) {
				throw new Saml2Exception(e);
			}
		}
		else if (object instanceof ResponseType) {
			try {
				XMLStreamWriter streamWriter = StaxUtil.getXMLStreamWriter(writer);
				SAMLResponseWriter assertionWriter = new SAMLResponseWriter(streamWriter);
				assertionWriter.write((ResponseType) object);
				streamWriter.flush();
				return writer.getBuffer().toString();
			} catch (ProcessingException | XMLStreamException e) {
				throw new Saml2Exception(e);
			}
		}
		else if (object instanceof Saml2LogoutResponseType) {
			try {
				XMLStreamWriter streamWriter = StaxUtil.getXMLStreamWriter(writer);
				KeycloakSaml2LogoutResponseWriter responseWriter = new KeycloakSaml2LogoutResponseWriter(streamWriter);
				responseWriter.writeLogoutResponse((Saml2LogoutResponseType) object);
				streamWriter.flush();
				return writer.getBuffer().toString();
			} catch (ProcessingException | XMLStreamException e) {
				throw new Saml2Exception(e);
			}
		}
		else if (object instanceof LogoutRequestType) {
			try {
				XMLStreamWriter streamWriter = StaxUtil.getXMLStreamWriter(writer);
				SAMLRequestWriter requestWriter = new SAMLRequestWriter(streamWriter);
				requestWriter.write((LogoutRequestType) object);
				streamWriter.flush();
				return writer.getBuffer().toString();
			} catch (ProcessingException | XMLStreamException e) {
				throw new Saml2Exception(e);
			}
		}
		else {
			throw new UnsupportedOperationException();
		}
	}

	private String signObject(String xml,
							  Saml2SignableObject signable) {
		KeycloakSaml2Signer signer = new KeycloakSaml2Signer(samlKeyStoreProvider);
		return signer.signOrEncrypt(signable, xml);
	}

	private List<RoleDescriptorType> getRoleDescriptors(Saml2Metadata<? extends Saml2Metadata> metadata) {
		List<RoleDescriptorType> result = new LinkedList<>();
		for (Saml2SsoProvider<? extends Saml2SsoProvider> p : metadata.getSsoProviders()) {
			RoleDescriptorType roleDescriptor = null;
			if (p instanceof Saml2ServiceProvider) {
				Saml2ServiceProvider sp = (Saml2ServiceProvider) p;
				SPSSODescriptorType descriptor = new SPSSODescriptorType(sp.getProtocolSupportEnumeration());
				roleDescriptor = descriptor;
				descriptor.setAuthnRequestsSigned(sp.isAuthnRequestsSigned());
				descriptor.setWantAssertionsSigned(sp.isWantAssertionsSigned());
				for (Saml2NameId id : p.getNameIds()) {
					descriptor.addNameIDFormat(id.toString());
				}
				for (int i = 0; i < sp.getAssertionConsumerService().size(); i++) {
					Saml2Endpoint ep = sp.getAssertionConsumerService().get(i);
					descriptor.addAssertionConsumerService(getIndexedEndpointType(ep, i));
				}
				for (int i = 0; i < sp.getArtifactResolutionService().size(); i++) {
					Saml2Endpoint ep = sp.getArtifactResolutionService().get(i);
					descriptor.addArtifactResolutionService(getArtifactResolutionService(ep, i));
				}
				for (int i = 0; i < sp.getSingleLogoutService().size(); i++) {
					Saml2Endpoint ep = sp.getSingleLogoutService().get(i);
					descriptor.addSingleLogoutService(getSingleLogoutService(ep));
				}
				if (sp.getRequestedAttributes() != null && !sp.getRequestedAttributes().isEmpty()) {
					descriptor.addAttributeConsumerService(getAttributeConsumingService(sp.getRequestedAttributes()));
				}

			}
			else if (p instanceof Saml2IdentityProvider) {
				Saml2IdentityProvider idp = (Saml2IdentityProvider) p;
				IDPSSODescriptorType descriptor = new IDPSSODescriptorType(
					ofNullable(idp.getProtocolSupportEnumeration()).orElse(emptyList())
				);
				roleDescriptor = descriptor;
				descriptor.setWantAuthnRequestsSigned(idp.getWantAuthnRequestsSigned());
				for (Saml2NameId id : p.getNameIds()) {
					descriptor.addNameIDFormat(id.toString());
				}
				for (int i = 0; i < idp.getSingleSignOnService().size(); i++) {
					Saml2Endpoint ep = idp.getSingleSignOnService().get(i);
					descriptor.addSingleSignOnService(getSingleSignOnService(ep, i));
				}
				for (int i = 0; i < p.getSingleLogoutService().size(); i++) {
					Saml2Endpoint ep = p.getSingleLogoutService().get(i);
					descriptor.addSingleLogoutService(getSingleLogoutService(ep));
				}
				for (int i = 0; i < p.getArtifactResolutionService().size(); i++) {
					Saml2Endpoint ep = p.getArtifactResolutionService().get(i);
					descriptor.addArtifactResolutionService(getArtifactResolutionService(ep, i));
				}
			}
			long now = getTime().millis();
			if (p.getCacheDuration() != null) {
				roleDescriptor.setCacheDuration(p.getCacheDuration());
			}
			roleDescriptor.setValidUntil(getXmlGregorianCalendar(p.getValidUntil()));
			//roleDescriptor.addSupportedProtocol(NS_PROTOCOL);
			roleDescriptor.setID(ofNullable(p.getId()).orElse("RD"+UUID.randomUUID().toString()));

			for (Saml2KeyData key : p.getKeys()) {
				roleDescriptor.addKeyDescriptor(getKeyDescriptor(key));
			}

			//md:extensions
			Saml2Endpoint requestInitiation = p.getRequestInitiation();
			Saml2Endpoint discovery = p.getDiscovery();
			if (requestInitiation != null || discovery != null) {
				ExtensionsType extensionsType = new ExtensionsType();
				if (requestInitiation != null) {
					try {
						EndpointType ri = new EndpointType(
							requestInitiation.getBinding().getValue(),
							new URI(requestInitiation.getLocation())
						);
						if (hasText(requestInitiation.getResponseLocation())) {
							ri.setResponseLocation(new URI(requestInitiation.getResponseLocation()));
						}
						extensionsType.addExtension(ri);
					} catch (URISyntaxException e) {
						throw new Saml2Exception(e);
					}
				}
				if (discovery != null) {
					try {
						IndexedEndpointType d = new IndexedEndpointType(
							discovery.getBinding().getValue(),
							new URI(discovery.getLocation())
						);
						if (hasText(discovery.getResponseLocation())) {
							d.setResponseLocation(new URI(requestInitiation.getResponseLocation()));
						}
						if (discovery.getIndex() >= 0) {
							d.setIndex(discovery.getIndex());
						}
						d.setIsDefault(discovery.isDefault() ? true : null);
						extensionsType.addExtension(d);
					} catch (URISyntaxException e) {
						throw new Saml2Exception(e);
					}
				}
				roleDescriptor.setExtensions(extensionsType);
			}
			roleDescriptor.setID(p.getId());
			result.add(roleDescriptor);
		}
		return result;
	}

	private XMLGregorianCalendar getXmlGregorianCalendar(DateTime date) {
		return Saml2DateUtils.toXmlGregorianCalendar(date);
	}

	private NameIDPolicyType getNameIDPolicy(
		Saml2NameIdPolicy nameIdPolicy
	) {
		NameIDPolicyType result = null;
		if (nameIdPolicy != null) {
			result = new NameIDPolicyType();
			result.setAllowCreate(nameIdPolicy.getAllowCreate());
			result.setFormat(nameIdPolicy.getFormat().getValue());
			result.setSPNameQualifier(nameIdPolicy.getSpNameQualifier());
		}
		return result;
	}

	private RequestedAuthnContextType getRequestedAuthenticationContext(Saml2AuthenticationRequest request) {
		RequestedAuthnContextType result = null;
		if (request.getRequestedAuthenticationContext() != null) {
			result = new RequestedAuthnContextType();
			switch (request.getRequestedAuthenticationContext()) {
				case exact:
					result.setComparison(AuthnContextComparisonType.EXACT);
					break;
				case better:
					result.setComparison(AuthnContextComparisonType.BETTER);
					break;
				case maximum:
					result.setComparison(AuthnContextComparisonType.MAXIMUM);
					break;
				case minimum:
					result.setComparison(AuthnContextComparisonType.MINIMUM);
					break;
				default:
					result.setComparison(AuthnContextComparisonType.EXACT);
					break;
			}
			if (request.getAuthenticationContextClassReference() != null) {
				result.addAuthnContextClassRef(request.getAuthenticationContextClassReference().toString());
			}
		}
		return result;
	}

	private NameIDType toIssuer(Saml2Issuer issuer) {
		NameIDType result = new NameIDType();
		result.setValue(issuer.getValue());
		if (issuer.getFormat() != null) {
			result.setFormat(issuer.getFormat().getValue());
		}
		result.setSPNameQualifier(issuer.getSpNameQualifier());
		result.setNameQualifier(issuer.getNameQualifier());
		return result;
	}

	private IndexedEndpointType getIndexedEndpointType(Saml2Endpoint endpoint, int index) {
		try {
			IndexedEndpointType result = new IndexedEndpointType(
				endpoint.getBinding().getValue(),
				new URI(endpoint.getLocation())
			);
			if (index > 0) {
				result.setIndex(index);
			}
			result.setIsDefault(endpoint.isDefault() ? true : null);
			return result;
		} catch (URISyntaxException e) {
			throw new Saml2Exception(e);
		}
	}

	private IndexedEndpointType getArtifactResolutionService(Saml2Endpoint ep, int i) {
		return getIndexedEndpointType(ep, i);
	}

	private IndexedEndpointType getSingleLogoutService(Saml2Endpoint endpoint) {
		return getIndexedEndpointType(endpoint, -1);
	}

	private AttributeConsumingServiceType getAttributeConsumingService(List<Saml2Attribute> attributes) {
		AttributeConsumingServiceType service = new AttributeConsumingServiceType(0);
		service.setIsDefault(true);
		for (Saml2Attribute a : attributes) {
			RequestedAttributeType ra = new RequestedAttributeType(a.getName());
			ra.setIsRequired(a.isRequired());
			ra.setFriendlyName(a.getFriendlyName());
			ra.setName(a.getName());
			ra.setNameFormat(a.getNameFormat().toString());
			service.addRequestedAttribute(ra);
		}
		return service;
	}

	private IndexedEndpointType getSingleSignOnService(Saml2Endpoint endpoint, int index) {
		return getIndexedEndpointType(endpoint, index);
	}

	private KeyDescriptorType getKeyDescriptor(Saml2KeyData key) {
		KeyDescriptorType descriptor = new KeyDescriptorType();
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document doc = db.newDocument();
			Element x509Cert = doc.createElementNS(NS_SIGNATURE, "ds:X509Certificate");
			x509Cert.setTextContent(Saml2X509Utils.keyCleanup(key.getCertificate()));
			Element x509Data = doc.createElementNS(NS_SIGNATURE, "ds:X509Data");
			x509Data.appendChild(x509Cert);
			Element keyInfo = doc.createElementNS(NS_SIGNATURE, "ds:KeyInfo");
			keyInfo.appendChild(x509Data);
			descriptor.setKeyInfo(keyInfo);
			if (key.getType() != null) {
				switch (key.getType()) {
					case SIGNING:
						descriptor.setUse(KeyTypes.SIGNING);
						break;
					case ENCRYPTION:
						descriptor.setUse(KeyTypes.ENCRYPTION);
						break;
					case UNSPECIFIED:
						break;
				}
			}
			else {
				descriptor.setUse(KeyTypes.SIGNING);
			}
			return descriptor;
		} catch (SecurityException | ParserConfigurationException e) {
			throw new Saml2KeyException(e);
		}
	}

	private class DecryptedData {
		private final Object decryptedData;
		private final Saml2KeyData decryptionKey;

		private DecryptedData(Object decryptedData, Saml2KeyData decryptionKey) {
			this.decryptedData = decryptedData;
			this.decryptionKey = decryptionKey;
		}

		Object getDecryptedData() {
			return decryptedData;
		}

	}

	private DecryptedData decrypt(EncryptedElementType encrypted, List<Saml2KeyData> keys) {
		Element element = encrypted.getEncryptedElement();
		Document encryptedAssertionDocument = null;
		try {
			encryptedAssertionDocument = DocumentUtil.createDocument();
		} catch (ConfigurationException e) {
			throw new Saml2Exception(e);
		}
		encryptedAssertionDocument.appendChild(encryptedAssertionDocument.importNode(element, true));
		Exception last = null;
		for (Saml2KeyData k : keys) {
			try {
				KeycloakSaml2KeyInfo info = new KeycloakSaml2KeyInfo(getSamlKeyStoreProvider(), k);
				Element result =
					XMLEncryptionUtil.decryptElementInDocument(
						encryptedAssertionDocument,
						info.getKeyPair().getPrivate()
					);
				Object parse = samlParser.parse(result);
				return new DecryptedData(parse, k);
			} catch (Exception x) {
				last = x;
			}
		}
		if (last != null) {
			throw new Saml2KeyException("Unable to decrypt object.", last);
		}
		return null;
	}

	private Saml2ObjectHolder parse(byte[] xml) {
		try {
			InputStream reader = new ByteArrayInputStream(xml);
			Document samlDocument = DocumentUtil.getDocument(reader);
			JAXPValidationUtil.checkSchemaValidation(samlDocument);
			//check for signatures
			NodeList signature = samlDocument.getElementsByTagNameNS(NS_SIGNATURE, "Signature");
			if (signature != null && signature.getLength() > 0) {
				configureIdAttribute(samlDocument);
			}
			Object object = samlParser.parse(samlDocument);
			return new Saml2ObjectHolder(samlDocument, object);
		} catch (Exception e) {
			throw new Saml2Exception(e);
		}
	}

	private List<? extends Saml2Provider> getSsoProviders(EntityDescriptorType descriptor) {
		final List<Saml2SsoProvider> providers = new LinkedList<>();
		List<SSODescriptorType> roles = new LinkedList<>();
		descriptor.getChoiceType().stream()
			.forEach(ct -> ct.getDescriptors().stream().forEach(
				d -> {
					if (d.getIdpDescriptor() != null) {
						roles.add(d.getIdpDescriptor());
					}
					if (d.getSpDescriptor() != null) {
						roles.add(d.getSpDescriptor());
					}
				}
			));

		for (SSODescriptorType roleDescriptor : roles) {
			providers.add(getSsoProvider(roleDescriptor));
		}
		return providers;
	}

	private Saml2SsoProvider getSsoProvider(SSODescriptorType descriptor) {
		if (descriptor instanceof SPSSODescriptorType) {
			SPSSODescriptorType desc = (SPSSODescriptorType) descriptor;
			Saml2ServiceProvider provider = new Saml2ServiceProvider();
			provider.setId(desc.getID());
			provider.setValidUntil(toDateTime(desc.getValidUntil()));
			if (desc.getCacheDuration() != null) {
				provider.setCacheDuration(desc.getCacheDuration());
			}
			provider.setProtocolSupportEnumeration(desc.getProtocolSupportEnumeration());
			provider.setNameIds(getNameIDs(desc.getNameIDFormat()));
			provider.setArtifactResolutionService(getEndpoints(desc.getArtifactResolutionService()));
			provider.setSingleLogoutService(getEndpoints(desc.getSingleLogoutService()));
			provider.setManageNameIDService(getEndpoints(desc.getManageNameIDService()));
			provider.setAuthnRequestsSigned(desc.isAuthnRequestsSigned());
			provider.setWantAssertionsSigned(desc.isWantAssertionsSigned());
			provider.setAssertionConsumerService(getEndpoints(desc.getAssertionConsumerService()));
			provider.setRequestedAttributes(getRequestAttributes(desc));
			provider.setKeys(getProviderKeys(descriptor));
			provider.setDiscovery(getDiscovery(desc));
			provider.setRequestInitiation(getRequestInitiation(desc));
			//TODO
			//provider.setAttributeConsumingService(getEndpoints(desc.getAttributeConsumingServices()));
			return provider;
		}
		else if (descriptor instanceof IDPSSODescriptorType) {
			IDPSSODescriptorType desc = (IDPSSODescriptorType) descriptor;
			Saml2IdentityProvider provider = new Saml2IdentityProvider();
			provider.setId(desc.getID());
			provider.setValidUntil(toDateTime(desc.getValidUntil()));
			if (desc.getCacheDuration() != null) {
				provider.setCacheDuration(desc.getCacheDuration());
			}
			provider.setProtocolSupportEnumeration(desc.getProtocolSupportEnumeration());
			provider.setNameIds(getNameIDs(desc.getNameIDFormat()));
			provider.setArtifactResolutionService(getEndpoints(desc.getArtifactResolutionService()));
			provider.setSingleLogoutService(getEndpoints(desc.getSingleLogoutService()));
			provider.setManageNameIDService(getEndpoints(desc.getManageNameIDService()));
			provider.setWantAuthnRequestsSigned(desc.isWantAuthnRequestsSigned());
			provider.setSingleSignOnService(getEndpoints(desc.getSingleSignOnService()));
			provider.setKeys(getProviderKeys(descriptor));
			provider.setDiscovery(getDiscovery(desc));
			provider.setRequestInitiation(getRequestInitiation(desc));
			return provider;
		}
		throw new UnsupportedOperationException(
			descriptor == null ?
				null :
				descriptor.getClass().getName()
		);
	}

	private List<Saml2Attribute> getRequestAttributes(SPSSODescriptorType desc) {
		List<Saml2Attribute> result = new LinkedList<>();
		for (AttributeConsumingServiceType s : ofNullable(desc.getAttributeConsumingService()).orElse(emptyList())) {
			if (s != null) {
				//take the first one
				result.addAll(getRequestedAttributes(s.getRequestedAttribute()));
				break;
			}
		}
		return result;
	}

	private Saml2Endpoint getRequestInitiation(RoleDescriptorType desc) {
		Saml2Endpoint result = null;
		if (desc.getExtensions() == null) {
			return null;
		}
		for (Object obj : desc.getExtensions().getAny()) {
			if (obj instanceof Element) {
				Element e = (Element) obj;
				if ("RequestInitiator".equals(e.getLocalName())) {
					String binding = e.getAttribute("Binding");
					String location = e.getAttribute("Location");
					String responseLocation = e.getAttribute("ResponseLocation");
					String index = e.getAttribute("index");
					String isDefault = e.getAttribute("isDefault");
					result = new Saml2Endpoint()
						.setIndex(hasText(index) ? Integer.valueOf(index) : 0)
						.setDefault(hasText(isDefault) ? Boolean.valueOf(isDefault) : false)
						.setBinding(hasText(binding) ? Saml2Binding.fromUrn(binding) : Saml2Binding.REQUEST_INITIATOR)
						.setLocation(location)
						.setResponseLocation(responseLocation);
				}
			}
		}
		return result;
	}

	private Saml2Endpoint getDiscovery(RoleDescriptorType desc) {
		Saml2Endpoint result = null;
		if (desc.getExtensions() == null) {
			return null;
		}
		for (Object obj : desc.getExtensions().getAny()) {
			if (obj instanceof Element) {
				Element e = (Element) obj;
				if ("DiscoveryResponse".equals(e.getLocalName())) {
					String binding = e.getAttribute("Binding");
					String location = e.getAttribute("Location");
					String responseLocation = e.getAttribute("ResponseLocation");
					String index = e.getAttribute("index");
					String isDefault = e.getAttribute("isDefault");
					result = new Saml2Endpoint()
						.setIndex(hasText(index) ? Integer.valueOf(index) : 0)
						.setDefault(hasText(isDefault) ? Boolean.valueOf(isDefault) : false)
						.setBinding(hasText(binding) ? Saml2Binding.fromUrn(binding) : Saml2Binding.DISCOVERY)
						.setLocation(location)
						.setResponseLocation(responseLocation);
				}
			}
		}
		return result;
	}

	private List<Saml2KeyData> getProviderKeys(SSODescriptorType descriptor) {
		List<Saml2KeyData> result = new LinkedList<>();
		for (KeyDescriptorType desc : ofNullable(descriptor.getKeyDescriptor()).orElse(emptyList())) {
			if (desc != null) {
				result.addAll(getKeyFromDescriptor(desc));
			}
		}
		return result;
	}

	private List<Saml2KeyData> getKeyFromDescriptor(KeyDescriptorType desc) {
		List<Saml2KeyData> result = new LinkedList<>();
		if (desc.getKeyInfo() == null) {
			return null;
		}
		Saml2KeyType type = desc.getUse() != null ? Saml2KeyType.valueOf(desc.getUse().name()) : Saml2KeyType.UNSPECIFIED;
		int index = 0;
		result.add(
			new Saml2KeyData(
				type.getTypeName() + "-" + (index++),
				null,
				desc.getKeyInfo().getFirstChild().getTextContent(),
				null,
				type
			)
		);

		return result;
	}

	private List<Saml2Endpoint> getEndpoints(List<? extends EndpointType> services) {
		List<Saml2Endpoint> result = new LinkedList<>();
		if (services != null) {
			services
				.stream()
				.forEach(s -> {
						Saml2Endpoint endpoint = new Saml2Endpoint()
							.setBinding(Saml2Binding.fromUrn(s.getBinding()))
							.setLocation(s.getLocation().toString());
						if (s.getResponseLocation() != null) {
							endpoint.setResponseLocation(s.getResponseLocation().toString());
						}
						result.add(endpoint);
						if (s instanceof IndexedEndpointType) {
							IndexedEndpointType idxEndpoint = (IndexedEndpointType) s;
							endpoint
								.setIndex(idxEndpoint.getIndex())
								.setDefault(idxEndpoint.isIsDefault() != null ? idxEndpoint.isIsDefault() : false);
						}
					}
				);
		}
		return result;
	}

	private List<Saml2NameId> getNameIDs(List<? extends Object> nameIDFormats) {
		List<Saml2NameId> result = new LinkedList<>();
		for (Object o : ofNullable(nameIDFormats).orElse(emptyList())) {
			if (o == null) {
				continue;
			}
			else if (o instanceof String) {
				result.add(Saml2NameId.fromUrn((String) o));
			}
			else if (o instanceof NameIDType) {
				NameIDType t = (NameIDType) o;
				result.add(Saml2NameId.fromUrn(t.getFormat().toString()));
			}
		}
		return result;
	}

	private ResponseType internalToXml(Saml2ResponseSaml2 response) {
		if (!hasText(response.getId())) {
			response.setId("R" + UUID.randomUUID().toString());
		}
		ResponseType result = new ResponseType(
			response.getId(),
			getXmlGregorianCalendar(response.getIssueInstant())
		);
		result.setConsent(response.getConsent());
		result.setInResponseTo(response.getInResponseTo());
		result.setDestination(response.getDestination());
		result.setIssuer(toIssuer(response.getIssuer()));

		if (response.getStatus() == null || response.getStatus().getCode() == null) {
			throw new Saml2Exception("Status cannot be null on a response");
		}

		StatusCodeType code = new StatusCodeType();
		code.setValue(response.getStatus().getCode().toUri());
		StatusType status = new StatusType();
		status.setStatusCode(code);

		if (hasText(response.getStatus().getMessage())) {
			status.setStatusMessage(response.getStatus().getMessage());
		}
		result.setStatus(status);

		for (Saml2Assertion a : ofNullable(response.getAssertions()).orElse(emptyList())) {
			AssertionType osAssertion = internalToXml(a);
			ResponseType.RTChoiceType assertionType;
			assertionType = new ResponseType.RTChoiceType(osAssertion);
			result.addAssertion(assertionType);
		}
		return result;

	}

	private Saml2LogoutResponseType internalToXml(Saml2LogoutResponse response) {
		if (!hasText(response.getId())) {
			response.setId("L" + UUID.randomUUID().toString());
		}
		if (response.getIssueInstant() == null) {
			response.setIssueInstant(DateTime.now());
		}
		Saml2LogoutResponseType result = new Saml2LogoutResponseType(
			response.getId(),
			getXmlGregorianCalendar(response.getIssueInstant())
		);
		result.setInResponseTo(response.getInResponseTo());
		result.setDestination(response.getDestination());

		NameIDType issuer = new NameIDType();
		issuer.setValue(response.getIssuer().getValue());
		issuer.setNameQualifier(response.getIssuer().getNameQualifier());
		issuer.setSPNameQualifier(response.getIssuer().getSpNameQualifier());
		result.setIssuer(issuer);

		StatusType status = new StatusType();
		StatusCodeType code = new StatusCodeType();
		try {
			code.setValue(new URI(response.getStatus().getCode().toString()));
		} catch (URISyntaxException e) {
			throw new Saml2Exception(e);
		}
		status.setStatusCode(code);
		status.setStatusMessage(response.getStatus().getMessage());
		result.setStatus(status);
		return result;
	}

	private LogoutRequestType internalToXml(Saml2LogoutSaml2Request request) {
		if (!hasText(request.getId())) {
			request.setId("L" + UUID.randomUUID().toString());
		}
		if (request.getIssueInstant() == null) {
			request.setIssueInstant(DateTime.now());
		}
		LogoutRequestType lr =
			new LogoutRequestType(request.getId(), getXmlGregorianCalendar(request.getIssueInstant()));
		try {
			lr.setDestination(new URI(request.getDestination().getLocation()));
		} catch (URISyntaxException e) {
			throw new Saml2Exception(e);
		}
		NameIDType issuer = new NameIDType();
		issuer.setValue(request.getIssuer().getValue());
		issuer.setNameQualifier(request.getIssuer().getNameQualifier());
		issuer.setSPNameQualifier(request.getIssuer().getSpNameQualifier());
		lr.setIssuer(issuer);

		lr.setNotOnOrAfter(getXmlGregorianCalendar(request.getNotOnOrAfter()));

		NameIDType nameID = new NameIDType();
		nameID.setFormat(request.getNameId().getFormat().getValue());
		nameID.setValue(request.getNameId().getValue());
		nameID.setSPNameQualifier(request.getNameId().getSpNameQualifier());
		nameID.setNameQualifier(request.getNameId().getNameQualifier());
		lr.setNameID(nameID);
		return lr;
	}

	private AssertionType internalToXml(Saml2Assertion request) {
		if (!hasText(request.getId())) {
			request.setId("A" + UUID.randomUUID().toString());
		}
		XMLGregorianCalendar instant =
			getXmlGregorianCalendar(ofNullable(request.getIssueInstant()).orElse(DateTime.now()));
		AssertionType a = new AssertionType(request.getId(), instant);
		a.setIssuer(getIssuer(request.getIssuer()));
		a.setSubject(getSubject(request.getSubject()));
		a.setConditions(getConditions(request.getConditions()));

		for (Saml2AuthenticationStatement stmt : request.getAuthenticationStatements()) {
			AuthnStatementType authnStatement = getAuthnStatementType(stmt);
			a.addStatement(authnStatement);
		}

		for (Saml2Attribute attribute : request.getAttributes()) {
			AttributeStatementType ast = new AttributeStatementType();
			AttributeType at = new AttributeType(attribute.getName());
			at.setFriendlyName(attribute.getFriendlyName());
			at.setNameFormat(attribute.getNameFormat().toString());
			for (Object o : attribute.getValues()) {
				if (o != null) {
					if (o instanceof DateTime) {
						at.addAttributeValue(toZuluTime((DateTime) o));
					}
					else {
						at.addAttributeValue(o.toString());
					}
				}
			}
			AttributeStatementType.ASTChoiceType choice = new AttributeStatementType.ASTChoiceType(at);
			ast.addAttribute(choice);
			a.addStatement(ast);
		}

		return a;
	}

	private AuthnStatementType getAuthnStatementType(Saml2AuthenticationStatement stmt) {
		AuthnStatementType authnStatement = new AuthnStatementType(getXmlGregorianCalendar(stmt.getAuthInstant()));
		AuthnContextType actx = new AuthnContextType();
		if (stmt.getAuthenticationContext().getClassReference() != null) {
			AuthnContextClassRefType aref = null;
			try {
				aref = new AuthnContextClassRefType(
					new URI(stmt.getAuthenticationContext().getClassReference().toString())
				);
			} catch (URISyntaxException e) {
				throw new Saml2Exception(e);
			}
			AuthnContextType.AuthnContextTypeSequence sequence = actx.new AuthnContextTypeSequence();
			sequence.setClassRef(aref);
			actx.setSequence(sequence);
		}

		authnStatement.setAuthnContext(actx);
		authnStatement.setSessionIndex(stmt.getSessionIndex());
		authnStatement.setSessionNotOnOrAfter(getXmlGregorianCalendar(stmt.getSessionNotOnOrAfter()));
		return authnStatement;
	}

	private Saml2NameIdPolicy fromNameIDPolicy(NameIDPolicyType nameIDPolicy) {
		Saml2NameIdPolicy result = null;
		if (nameIDPolicy != null) {
			result = new Saml2NameIdPolicy()
				.setAllowCreate(nameIDPolicy.isAllowCreate())
				.setFormat(Saml2NameId.fromUrn(nameIDPolicy.getFormat().toString()))
				.setSpNameQualifier(nameIDPolicy.getSPNameQualifier());
		}
		return result;
	}

	private Saml2ResponseSaml2 resolveResponse(
		ResponseType parsed,
		Map<String, Saml2Signature> signatureMap,
		List<Saml2KeyData> localKeys
	) {
		Saml2ResponseSaml2 result = new Saml2ResponseSaml2()
			.setConsent(parsed.getConsent())
			.setDestination(parsed.getDestination())
			.setId(parsed.getID())
			.setInResponseTo(parsed.getInResponseTo())
			.setIssueInstant(toDateTime(parsed.getIssueInstant()))
			.setIssuer(getIssuer(parsed.getIssuer()))
			.setVersion(parsed.getVersion())
			.setStatus(getStatus(parsed.getStatus()))
			.setAssertions(
				parsed.getAssertions().stream()
					.filter(a -> a.getAssertion() != null)
					.map(a -> resolveAssertion(a.getAssertion(), signatureMap, localKeys, false)
					)
					.collect(Collectors.toList())
			);
		List<EncryptedAssertionType> encryptedAssertions = parsed.getAssertions().stream()
			.filter(a -> a.getEncryptedAssertion() != null)
			.map(a -> a.getEncryptedAssertion())
			.collect(Collectors.toList());
		if (!encryptedAssertions.isEmpty()) {
			encryptedAssertions
				.stream()
				.forEach(
					a -> result.addAssertion(
						resolveAssertion(
							(AssertionType) decrypt(a, localKeys).getDecryptedData(),
							signatureMap,
							localKeys,
							true
						)
					)
				);
		}
		KeycloakSaml2SignatureValidator.assignSignatureToObject(signatureMap, result, parsed.getSignature());
		return result;

	}

	private NameIDType getIssuer(Saml2Issuer issuer) {
		if (issuer == null) {
			return null;
		}
		NameIDType result = new NameIDType();
		result.setNameQualifier(issuer.getNameQualifier());
		result.setSPNameQualifier(issuer.getSpNameQualifier());
		result.setValue(issuer.getValue());
		try {
			result.setFormat(
				issuer.getFormat() == null ?
					null :
					new URI(issuer.getFormat().toString())
			);
		} catch (URISyntaxException e) {
			throw new Saml2Exception(e);
		}
		return result;
	}

	private Saml2Issuer getIssuer(NameIDType issuer) {
		if (issuer == null) {
			return null;
		}
		Saml2Issuer result = new Saml2Issuer()
			.setValue(issuer.getValue())
			.setSpNameQualifier(issuer.getSPNameQualifier())
			.setNameQualifier(issuer.getNameQualifier());
		if (issuer.getFormat() != null) {
			result.setFormat(Saml2NameId.fromUrn(issuer.getFormat().toString()));
		}
		return result;
	}

	private Saml2Status getStatus(StatusType status) {
		return new Saml2Status()
			.setCode(Saml2StatusCode.fromUrn(status.getStatusCode().getValue().toString()))
			.setMessage(status.getStatusMessage());
	}

	private Saml2Assertion resolveAssertion(
		AssertionType parsed,
		Map<String, Saml2Signature> signatureMap,
		List<Saml2KeyData> localKeys,
		boolean encrypted
	) {
		Saml2Assertion assertion = new Saml2Assertion(encrypted)
			.setId(parsed.getID())
			.setIssueInstant(toDateTime(parsed.getIssueInstant()))
			.setVersion(parsed.getVersion())
			.setIssuer(getIssuer(parsed.getIssuer()))
			.setSubject(getSubject(parsed.getSubject(), localKeys))
			.setConditions(getConditions(parsed.getConditions()))
			.setAuthenticationStatements(getAuthenticationStatements(parsed.getStatements()))
			.setAttributes(getAttributes(parsed.getAttributeStatements(), localKeys))
			.setImplementation(parsed);
		KeycloakSaml2SignatureValidator.assignSignatureToObject(signatureMap, assertion, parsed.getSignature());
		return assertion;
	}


	private SubjectType getSubject(Saml2Subject subject) {
		try {
			if (subject == null) {
				return null;
			}

			NameIDType principal = new NameIDType();
			principal.setValue(subject.getPrincipal().getValue());
			principal.setSPProvidedID(subject.getPrincipal().getSpProvidedId());
			principal.setSPNameQualifier(subject.getPrincipal().getSpNameQualifier());
			principal.setNameQualifier(subject.getPrincipal().getNameQualifier());
			principal.setFormat(new URI(subject.getPrincipal().getFormat().toString()));

			SubjectType.STSubType subType = new SubjectType.STSubType();
			subType.addBaseID(principal);

			for (Saml2SubjectConfirmation confirmation : subject.getConfirmations()) {
				SubjectConfirmationType ct = new SubjectConfirmationType();
				ct.setMethod(confirmation.getMethod().toString());
				if (confirmation.getNameId() != null) {
					NameIDType nameId = new NameIDType();
					nameId.setValue(confirmation.getNameId());
					if (confirmation.getFormat() != null) {
						nameId.setFormat(new URI(confirmation.getFormat().toString()));
					}
					ct.setNameID(nameId);
				}
				Saml2SubjectConfirmationData confirmationData = confirmation.getConfirmationData();
				if (confirmationData != null) {
					SubjectConfirmationDataType cdataType = new SubjectConfirmationDataType();
					cdataType.setInResponseTo(confirmationData.getInResponseTo());
					cdataType.setNotBefore(getXmlGregorianCalendar(confirmationData.getNotBefore()));
					cdataType.setNotOnOrAfter(getXmlGregorianCalendar(confirmationData.getNotOnOrAfter()));
					cdataType.setRecipient(confirmationData.getRecipient());
					ct.setSubjectConfirmationData(cdataType);
				}

				subType.addConfirmation(ct);
			}

			SubjectType result = new SubjectType();
			result.setSubType(subType);
			return result;
		} catch (URISyntaxException | NullPointerException e) {
			throw new Saml2Exception(e);
		}
	}

	private Saml2Subject getSubject(SubjectType subject, List<Saml2KeyData> localKeys) {

		return new Saml2Subject()
			.setPrincipal(getPrincipal(subject, localKeys))
			.setConfirmations(getConfirmations(subject.getConfirmation(), localKeys))
			;
	}

	private ConditionsType getConditions(Saml2Conditions conditions) {
		ConditionsType result = new ConditionsType();
		result.setNotBefore(getXmlGregorianCalendar(conditions.getNotBefore()));
		result.setNotOnOrAfter(getXmlGregorianCalendar(conditions.getNotOnOrAfter()));
		getCriteriaOut(conditions.getCriteria()).forEach(
			c -> result.addCondition(c)
		);
		return result;
	}

	private Saml2Conditions getConditions(ConditionsType conditions) {
		return new Saml2Conditions()
			.setNotBefore(toDateTime(conditions.getNotBefore()))
			.setNotOnOrAfter(toDateTime(conditions.getNotOnOrAfter()))
			.setCriteria(getCriteria(conditions.getConditions()));
	}

	private List<Saml2AuthenticationStatement> getAuthenticationStatements(Collection<StatementAbstractType> authnStatements) {
		List<Saml2AuthenticationStatement> result = new LinkedList<>();

		for (StatementAbstractType st : ofNullable(authnStatements).orElse(emptyList())) {
			if (st instanceof AuthnStatementType) {
				AuthnStatementType s = (AuthnStatementType) st;
				AuthnContextType authnContext = s.getAuthnContext();
				AuthnContextClassRefType authnContextClassRef = authnContext.getSequence().getClassRef();
				String ref = null;
				if (authnContextClassRef != null && authnContextClassRef.getValue() != null) {
					ref = authnContextClassRef.getValue().toString();
				}

				Saml2AuthenticationStatement statement = new Saml2AuthenticationStatement()
					.setSessionIndex(s.getSessionIndex())
					.setAuthInstant(toDateTime(s.getAuthnInstant()))
					.setAuthenticationContext(
						authnContext != null ?
							new Saml2AuthenticationContext()
								.setClassReference(Saml2AuthenticationContextClassReference.fromUrn(ref))
							: null
					);
				statement.setSessionNotOnOrAfter(toDateTime(s.getSessionNotOnOrAfter()));
				result.add(statement);

			}

		}
		return result;
	}

	private List<Saml2Attribute> getAttributes(
		Collection<AttributeStatementType> attributeStatements, List<Saml2KeyData>
		localKeys
	) {
		List<Saml2Attribute> result = new LinkedList<>();
		for (AttributeStatementType stmt : ofNullable(attributeStatements).orElse(emptyList())) {
			for (AttributeStatementType.ASTChoiceType a : ofNullable(stmt.getAttributes()).orElse(emptyList())) {
				if (a.getAttribute() != null) {
					result.add(
						new Saml2Attribute()
							.setFriendlyName(a.getAttribute().getFriendlyName())
							.setName(a.getAttribute().getName())
							.setNameFormat(Saml2AttributeNameFormat.fromUrn(a.getAttribute().getNameFormat()))
							.setValues(getJavaValues(a.getAttribute().getAttributeValue()))
					);
				}
				else if (a.getEncryptedAssertion() != null) {
					AttributeType at = (AttributeType) decrypt(a.getEncryptedAssertion(), localKeys).getDecryptedData();
					result.add(
						new Saml2Attribute()
							.setFriendlyName(at.getFriendlyName())
							.setName(at.getName())
							.setNameFormat(Saml2AttributeNameFormat.fromUrn(at.getNameFormat()))
							.setValues(getJavaValues(at.getAttributeValue()))
					);
				}
			}
		}
		return result;
	}

	private Saml2NameIdPrincipalSaml2 getPrincipal(SubjectType subject, List<Saml2KeyData> localKeys) {
		NameIDType p = getNameID(
			(NameIDType) subject.getSubType().getBaseID(),
			subject.getSubType().getEncryptedID(),
			localKeys
		);
		if (p != null) {
			return getNameIdPrincipal(p);
		}
		else {
			throw new UnsupportedOperationException("Currently only supporting NameID subject principals");
		}
	}

	private List<Saml2SubjectConfirmation> getConfirmations(List<SubjectConfirmationType> subjectConfirmations,
															List<Saml2KeyData> localKeys) {
		List<Saml2SubjectConfirmation> result = new LinkedList<>();
		for (SubjectConfirmationType s : subjectConfirmations) {
			NameIDType nameID = getNameID(s.getNameID(), s.getEncryptedID(), localKeys);
			Saml2SubjectConfirmationData confirmationData = new Saml2SubjectConfirmationData()
				.setRecipient(s.getSubjectConfirmationData().getRecipient())
				.setNotOnOrAfter(toDateTime(s.getSubjectConfirmationData().getNotOnOrAfter()))
				.setNotBefore(toDateTime(s.getSubjectConfirmationData().getNotBefore()))
				.setInResponseTo(s.getSubjectConfirmationData().getInResponseTo());
			result.add(
				new Saml2SubjectConfirmation()
					.setNameId(nameID != null ? nameID.getValue() : null)
					.setFormat(nameID != null ? Saml2NameId.fromUrn(nameID.getFormat().toString()) : null)
					.setMethod(Saml2SubjectConfirmationMethod.fromUrn(s.getMethod()))
					.setConfirmationData(
						confirmationData
					)
			);
		}
		return result;
	}

	private List<ConditionAbstractType> getCriteriaOut(List<Saml2AssertionCondition> conditions) {
		List<ConditionAbstractType> result = new LinkedList<>();
		ofNullable(conditions).orElse(emptyList()).forEach(
			c -> {
				if (c instanceof Saml2AudienceRestriction) {
					AudienceRestrictionType a = new AudienceRestrictionType();
					Saml2AudienceRestriction ar = (Saml2AudienceRestriction) c;
					for (String s : ofNullable(ar.getAudiences()).orElse(emptyList())) {
						try {
							a.addAudience(new URI(s));
						} catch (URISyntaxException e) {
							throw new Saml2Exception(e);
						}
					}
					result.add(a);
				}
				else if (c instanceof Saml2OneTimeUse) {
					OneTimeUseType one = new OneTimeUseType();
					result.add(one);
				}
			}

		);
		return result;
	}

	private List<Saml2AssertionCondition> getCriteria(List<ConditionAbstractType> conditions) {
		List<Saml2AssertionCondition> result = new LinkedList<>();
		for (ConditionAbstractType c : conditions) {
			if (c instanceof AudienceRestrictionType) {
				AudienceRestrictionType aud = (AudienceRestrictionType) c;

				if (aud.getAudience() != null) {
					result.add(
						new Saml2AudienceRestriction()
							.setAudiences(
								aud.getAudience().stream().map(
									a -> a.toString()
								).collect(Collectors.toList())
							)
					);
				}
			}
			else if (c instanceof OneTimeUseType) {
				result.add(new Saml2OneTimeUse());
			}
		}
		return result;
	}

	private List<Object> getJavaValues(List<Object> attributeValues) {
		List<Object> result = new LinkedList<>(attributeValues);
		return result;
	}

	private NameIDType getNameID(NameIDType id,
								 EncryptedElementType eid,
								 List<Saml2KeyData> localKeys) {
		NameIDType result = id;
		if (result == null && eid != null && eid.getEncryptedElement() != null) {
			result = (NameIDType) decrypt(eid, localKeys).getDecryptedData();
		}
		return result;
	}

	private Saml2LogoutResponse resolveLogoutResponse(StatusResponseType response,
													  Map<String, Saml2Signature> signatureMap,
													  List<Saml2KeyData> localKeys) {
		Saml2LogoutResponse result = new Saml2LogoutResponse()
			.setId(response.getID())
			.setInResponseTo(response.getInResponseTo())
			.setConsent(response.getConsent())
			.setVersion(response.getVersion())
			.setIssueInstant(toDateTime(response.getIssueInstant()))
			.setIssuer(getIssuer(response.getIssuer()))
			.setDestination(response.getDestination())
			.setStatus(getStatus(response.getStatus()));

		KeycloakSaml2SignatureValidator.assignSignatureToObject(signatureMap, result, response.getSignature());
		return result;
	}

	private Saml2LogoutSaml2Request resolveLogoutRequest(LogoutRequestType request,
														 Map<String, Saml2Signature> signatureMap,
														 List<Saml2KeyData> localKeys) {
		Saml2LogoutSaml2Request result = new Saml2LogoutSaml2Request()
			.setId(request.getID())
			.setConsent(request.getConsent())
			.setVersion(request.getVersion())
			.setNotOnOrAfter(toDateTime(request.getNotOnOrAfter()))
			.setIssueInstant(toDateTime(request.getIssueInstant()))
			.setReason(Saml2LogoutReason.fromUrn(request.getReason()))
			.setIssuer(getIssuer(request.getIssuer()))
			.setDestination(new Saml2Endpoint().setLocation(request.getDestination().toString()));
		NameIDType nameID = getNameID(request.getNameID(), request.getEncryptedID(), localKeys);
		result.setNameId(getNameIdPrincipal(nameID));
		KeycloakSaml2SignatureValidator.assignSignatureToObject(signatureMap, result, request.getSignature());
		return result;
	}

	private Saml2NameIdPrincipalSaml2 getNameIdPrincipal(NameIDType p) {
		return new Saml2NameIdPrincipalSaml2()
			.setSpNameQualifier(p.getSPNameQualifier())
			.setNameQualifier(p.getNameQualifier())
			.setFormat(Saml2NameId.fromUrn(p.getFormat().toString()))
			.setSpProvidedId(p.getSPProvidedID())
			.setValue(p.getValue());
	}

	private List<Saml2Attribute> getRequestedAttributes(List<RequestedAttributeType> attributes) {
		List<Saml2Attribute> result = new LinkedList<>();
		for (RequestedAttributeType a : ofNullable(attributes).orElse(emptyList())) {
			result.add(
				new Saml2Attribute()
					.setFriendlyName(a.getFriendlyName())
					.setName(a.getName())
					.setNameFormat(Saml2AttributeNameFormat.fromUrn(a.getNameFormat()))
					.setValues(getJavaValues(a.getAttributeValue()))
					.setRequired(a.isIsRequired())
			);
		}
		return result;
	}

	private Saml2AuthenticationRequest resolveAuthenticationRequest(AuthnRequestType parsed,
																	Map<String, Saml2Signature> signatureMap) {
		AuthnRequestType request = parsed;
		Saml2AuthenticationRequest result = new Saml2AuthenticationRequest()
			.setBinding(Saml2Binding.fromUrn(request.getProtocolBinding().toString()))
			.setAssertionConsumerService(
				getEndpoint(
					request.getAssertionConsumerServiceURL().toString(),
					Saml2Binding.fromUrn(request.getProtocolBinding().toString()),
					ofNullable(request.getAssertionConsumerServiceIndex()).orElse(-1),
					false
				)
			)
			.setDestination(
				getEndpoint(
					request.getDestination().toString(),
					Saml2Binding.fromUrn(request.getProtocolBinding().toString()),
					-1,
					false
				)
			)
			.setIssuer(getIssuer(request.getIssuer()))
			.setForceAuth(request.isForceAuthn())
			.setPassive(request.isIsPassive())
			.setId(request.getID())
			.setIssueInstant(toDateTime(request.getIssueInstant()))
			.setVersion(request.getVersion())
			.setRequestedAuthenticationContext(getRequestedAuthenticationContext(request))
			.setAuthenticationContextClassReference(getAuthenticationContextClassReference(request))
			.setNameIdPolicy(fromNameIDPolicy(request.getNameIDPolicy()));
		KeycloakSaml2SignatureValidator.assignSignatureToObject(signatureMap, result, request.getSignature());
		return result;
	}

	private Saml2AuthenticationContextClassReference getAuthenticationContextClassReference(AuthnRequestType request) {
		Saml2AuthenticationContextClassReference result = null;
		final RequestedAuthnContextType context = request.getRequestedAuthnContext();
		if (context != null && !CollectionUtils.isEmpty(context.getAuthnContextClassRef())) {
			final String urn = context.getAuthnContextClassRef().get(0);
			result = Saml2AuthenticationContextClassReference.fromUrn(urn);
		}
		return result;
	}

	private Saml2RequestedAuthenticationContext getRequestedAuthenticationContext(AuthnRequestType request) {
		Saml2RequestedAuthenticationContext result = null;

		if (request.getRequestedAuthnContext() != null) {
			AuthnContextComparisonType comparison = request.getRequestedAuthnContext().getComparison();
			if (null != comparison) {
				result = Saml2RequestedAuthenticationContext.fromName(comparison.toString());
			}
		}
		return result;
	}

	private Saml2Metadata resolveMetadata(EntitiesDescriptorType parsed,
										  Map<String, Saml2Signature> signatureMap) {
		Saml2Metadata result = null, current = null;
		for (Object object : parsed.getEntityDescriptor()) {
			EntityDescriptorType desc = (EntityDescriptorType) object;
			if (result == null) {
				result = resolveMetadata(desc, signatureMap);
				current = result;
			}
			else {
				Saml2Metadata m = resolveMetadata(desc, signatureMap);
				current.setNext(m);
				current = m;
			}
		}
		return result;
	}

	private Saml2Metadata resolveMetadata(EntityDescriptorType parsed,
										  Map<String, Saml2Signature> signatureMap) {
		EntityDescriptorType descriptor = parsed;
		List<? extends Saml2Provider> ssoProviders = getSsoProviders(descriptor);
		Saml2Metadata desc = getMetadata(ssoProviders);
		long duration = descriptor.getCacheDuration() != null ?
			descriptor.getCacheDuration().getTimeInMillis(new Date()) : -1;

		desc.setCacheDuration(toDuration(duration));
		desc.setEntityId(descriptor.getEntityID());
		if (isUrl(desc.getEntityId())) {
			desc.setEntityAlias(getHostFromUrl(desc.getEntityId()));
		}
		else {
			desc.setEntityAlias(desc.getEntityId());
		}

		desc.setId(descriptor.getID());
		desc.setValidUntil(toDateTime(descriptor.getValidUntil()));

		KeycloakSaml2SignatureValidator.assignSignatureToObject(signatureMap, desc, descriptor.getSignature());
		return desc;
	}

	private Saml2Metadata getMetadata(List<? extends Saml2Provider> ssoProviders) {
		Saml2Metadata result = determineMetadataType(ssoProviders);
		result.setProviders(ssoProviders);
		return result;
	}

	private Saml2Endpoint getEndpoint(String url, Saml2Binding binding, int index, boolean isDefault) {
		return
			new Saml2Endpoint()
				.setIndex(index)
				.setBinding(binding)
				.setLocation(url)
				.setDefault(isDefault)
				.setIndex(index);
	}

}
