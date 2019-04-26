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

package org.springframework.security.saml2.spi.opensaml;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.time.Clock;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import javax.crypto.SecretKey;
import javax.xml.datatype.Duration;
import javax.xml.namespace.QName;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.Saml2KeyException;
import org.springframework.security.saml2.spi.Saml2KeyStoreProvider;
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
import org.springframework.security.saml2.model.authentication.Saml2LogoutResponse;
import org.springframework.security.saml2.model.authentication.Saml2LogoutRequest;
import org.springframework.security.saml2.model.authentication.Saml2NameIdPolicy;
import org.springframework.security.saml2.model.authentication.Saml2NameIdPrincipal;
import org.springframework.security.saml2.model.authentication.Saml2OneTimeUse;
import org.springframework.security.saml2.model.authentication.Saml2RequestedAuthenticationContext;
import org.springframework.security.saml2.model.authentication.Saml2Response;
import org.springframework.security.saml2.model.authentication.Saml2Scoping;
import org.springframework.security.saml2.model.authentication.Saml2Status;
import org.springframework.security.saml2.model.authentication.Saml2StatusCode;
import org.springframework.security.saml2.model.authentication.Saml2Subject;
import org.springframework.security.saml2.model.authentication.Saml2SubjectConfirmation;
import org.springframework.security.saml2.model.authentication.Saml2SubjectConfirmationData;
import org.springframework.security.saml2.model.authentication.Saml2SubjectConfirmationMethod;
import org.springframework.security.saml2.model.encrypt.Saml2DataEncryptionMethod;
import org.springframework.security.saml2.model.encrypt.Saml2KeyEncryptionMethod;
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
import org.springframework.security.saml2.model.signature.Saml2AlgorithmMethod;
import org.springframework.security.saml2.model.signature.Saml2CanonicalizationMethod;
import org.springframework.security.saml2.model.signature.Saml2DigestMethod;
import org.springframework.security.saml2.model.signature.Saml2Signature;
import org.springframework.security.saml2.model.signature.Saml2SignatureException;
import org.springframework.security.saml2.spi.Saml2JavaAbstraction;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.DOMTypeSupport;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.signature.XMLSignatureException;
import org.joda.time.DateTime;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.XSBase64Binary;
import org.opensaml.core.xml.schema.XSBoolean;
import org.opensaml.core.xml.schema.XSBooleanValue;
import org.opensaml.core.xml.schema.XSDateTime;
import org.opensaml.core.xml.schema.XSInteger;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.XSURI;
import org.opensaml.core.xml.schema.impl.XSAnyBuilder;
import org.opensaml.core.xml.schema.impl.XSBooleanBuilder;
import org.opensaml.core.xml.schema.impl.XSDateTimeBuilder;
import org.opensaml.core.xml.schema.impl.XSIntegerBuilder;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.opensaml.core.xml.schema.impl.XSURIBuilder;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.ext.idpdisco.DiscoveryResponse;
import org.opensaml.saml.ext.idpdisco.impl.DiscoveryResponseBuilder;
import org.opensaml.saml.ext.saml2mdreqinit.RequestInitiator;
import org.opensaml.saml.ext.saml2mdreqinit.impl.RequestInitiatorBuilder;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AuthenticatingAuthority;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Condition;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.EncryptedAttribute;
import org.opensaml.saml.saml2.core.EncryptedElementType;
import org.opensaml.saml.saml2.core.EncryptedID;
import org.opensaml.saml.saml2.core.IDPEntry;
import org.opensaml.saml.saml2.core.IDPList;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.RequesterID;
import org.opensaml.saml.saml2.core.Scoping;
import org.opensaml.saml.saml2.core.StatusMessage;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.saml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.AttributeConsumingService;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.IndexedEndpoint;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.RequestedAttribute;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml.saml2.metadata.impl.ExtensionsBuilder;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.config.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.encryption.support.ChainingEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.impl.SignatureImpl;
import org.opensaml.xmlsec.signature.support.ContentReference;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import static java.lang.String.format;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Optional.ofNullable;
import static org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration.EXACT;
import static org.opensaml.security.crypto.KeySupport.generateKey;
import static org.springframework.security.saml2.model.Saml2Namespace.NS_PROTOCOL;
import static org.springframework.security.saml2.util.Saml2StringUtils.getHostFromUrl;
import static org.springframework.security.saml2.util.Saml2StringUtils.isUrl;
import static org.springframework.util.StringUtils.hasText;

public class OpenSaml2Implementation extends Saml2JavaAbstraction<OpenSaml2Implementation> {

	private static final Log logger = LogFactory.getLog(OpenSaml2Implementation.class);
	private BasicParserPool parserPool;
	private ChainingEncryptedKeyResolver encryptedKeyResolver;
	private Saml2KeyStoreProvider samlKeyStoreProvider = new Saml2KeyStoreProvider() {
	};

	public OpenSaml2Implementation(Clock time) {
		super(time);
		this.parserPool = new BasicParserPool();
	}

	public OpenSaml2Implementation setSamlKeyStoreProvider(Saml2KeyStoreProvider samlKeyStoreProvider) {
		this.samlKeyStoreProvider = samlKeyStoreProvider;
		return this;
	}

	private BasicParserPool getParserPool() {
		return parserPool;
	}

	private MarshallerFactory getMarshallerFactory() {
		return XMLObjectProviderRegistrySupport.getMarshallerFactory();
	}

	private UnmarshallerFactory getUnmarshallerFactory() {
		return XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
	}

	private EntityDescriptor getEntityDescriptor() {
		XMLObjectBuilderFactory builderFactory = getBuilderFactory();
		SAMLObjectBuilder<EntityDescriptor> builder =
			(SAMLObjectBuilder<EntityDescriptor>) builderFactory.getBuilder(EntityDescriptor
				.DEFAULT_ELEMENT_NAME);
		return builder.buildObject();
	}

	private SPSSODescriptor getSPSSODescriptor() {
		SAMLObjectBuilder<SPSSODescriptor> builder =
			(SAMLObjectBuilder<SPSSODescriptor>) getBuilderFactory().getBuilder(SPSSODescriptor
				.DEFAULT_ELEMENT_NAME);
		return builder.buildObject();
	}

	private IDPSSODescriptor getIDPSSODescriptor() {
		SAMLObjectBuilder<IDPSSODescriptor> builder =
			(SAMLObjectBuilder<IDPSSODescriptor>) getBuilderFactory().getBuilder(IDPSSODescriptor
				.DEFAULT_ELEMENT_NAME);
		return builder.buildObject();
	}

	private Extensions getMetadataExtensions() {
		SAMLObjectBuilder<Extensions> builder =
			(SAMLObjectBuilder<Extensions>) getBuilderFactory().getBuilder(Extensions.DEFAULT_ELEMENT_NAME);
		return builder.buildObject();
	}

	private XMLObjectBuilderFactory getBuilderFactory() {
		return XMLObjectProviderRegistrySupport.getBuilderFactory();
	}

	@Override
	protected void bootstrap() {
		//configure default values
		//maxPoolSize = 5;
		parserPool.setMaxPoolSize(50);
		//coalescing = true;
		parserPool.setCoalescing(true);
		//expandEntityReferences = false;
		parserPool.setExpandEntityReferences(false);
		//ignoreComments = true;
		parserPool.setIgnoreComments(true);
		//ignoreElementContentWhitespace = true;
		parserPool.setIgnoreElementContentWhitespace(true);
		//namespaceAware = true;
		parserPool.setNamespaceAware(true);
		//schema = null;
		parserPool.setSchema(null);
		//dtdValidating = false;
		parserPool.setDTDValidating(false);
		//xincludeAware = false;
		parserPool.setXincludeAware(false);

		Map<String, Object> builderAttributes = new HashMap<>();
		parserPool.setBuilderAttributes(builderAttributes);

		Map<String, Boolean> parserBuilderFeatures = new HashMap<>();
		parserBuilderFeatures.put("http://apache.org/xml/features/disallow-doctype-decl", TRUE);
		parserBuilderFeatures.put("http://javax.xml.XMLConstants/feature/secure-processing", TRUE);
		parserBuilderFeatures.put("http://xml.org/sax/features/external-general-entities", FALSE);
		parserBuilderFeatures.put(
			"http://apache.org/xml/features/validation/schema/normalized-value",
			FALSE
		);
		parserBuilderFeatures.put("http://xml.org/sax/features/external-parameter-entities", FALSE);
		parserBuilderFeatures.put("http://apache.org/xml/features/dom/defer-node-expansion", FALSE);
		parserPool.setBuilderFeatures(parserBuilderFeatures);

		try {
			parserPool.initialize();
		} catch (ComponentInitializationException x) {
			throw new Saml2Exception("Unable to initialize OpenSaml v3 ParserPool", x);
		}


		try {
			InitializationService.initialize();
		} catch (InitializationException e) {
			throw new Saml2Exception("Unable to initialize OpenSaml v3", e);
		}

		XMLObjectProviderRegistry registry;
		synchronized (ConfigurationService.class) {
			registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
			if (registry == null) {
				registry = new XMLObjectProviderRegistry();
				ConfigurationService.register(XMLObjectProviderRegistry.class, registry);
			}
		}

		registry.setParserPool(parserPool);
		encryptedKeyResolver = new ChainingEncryptedKeyResolver(
			asList(
				new InlineEncryptedKeyResolver(),
				new EncryptedElementTypeEncryptedKeyResolver(),
				new SimpleRetrievalMethodEncryptedKeyResolver()
			)
		);
	}

	@Override
	protected Duration toDuration(long millis) {
		if (millis < 0) {
			return null;
		}
		else {
			return DOMTypeSupport.getDataTypeFactory().newDuration(millis);
		}
	}

	@Override
	protected String toXml(Saml2Object saml2Object) {
		XMLObject result = null;
		if (saml2Object instanceof Saml2AuthenticationRequest) {
			result = internalToXml((Saml2AuthenticationRequest) saml2Object);
		}
		else if (saml2Object instanceof Saml2Assertion) {
			result = internalToXml((Saml2Assertion) saml2Object);
		}
		else if (saml2Object instanceof Saml2Metadata) {
			result = internalToXml((Saml2Metadata) saml2Object);
		}
		else if (saml2Object instanceof Saml2Response) {
			result = internalToXml((Saml2Response) saml2Object);
		}
		else if (saml2Object instanceof Saml2LogoutRequest) {
			result = internalToXml((Saml2LogoutRequest) saml2Object);
		}
		else if (saml2Object instanceof Saml2LogoutResponse) {
			result = internalToXml((Saml2LogoutResponse) saml2Object);
		}
		if (result != null) {
			return marshallToXml(result);
		}
		throw new Saml2Exception("To xml transformation not supported for: " +
			saml2Object != null ?
			saml2Object.getClass().getName() :
			"null"
		);
	}

	@Override
	protected Saml2Object resolve(byte[] xml, List<Saml2KeyData> verificationKeys, List<Saml2KeyData> localKeys) {
		XMLObject parsed = parse(xml);
		Saml2Signature signature = validateSignature((SignableSAMLObject) parsed, verificationKeys);
		Saml2Object result = null;
		if (parsed instanceof EntityDescriptor) {
			result = resolveMetadata((EntityDescriptor) parsed)
				.setSignature(signature);
		}
		else if (parsed instanceof EntitiesDescriptor) {
			result = resolveMetadata((EntitiesDescriptor) parsed, verificationKeys, localKeys);
		}
		else if (parsed instanceof AuthnRequest) {
			result = resolveAuthenticationRequest((AuthnRequest) parsed)
				.setSignature(signature);
		}
		else if (parsed instanceof org.opensaml.saml.saml2.core.Assertion) {
			result = resolveAssertion(
				(org.opensaml.saml.saml2.core.Assertion) parsed,
				verificationKeys,
				localKeys,
				false
			);
		}
		else if (parsed instanceof org.opensaml.saml.saml2.core.Response) {
			result = resolveResponse((org.opensaml.saml.saml2.core.Response) parsed, verificationKeys, localKeys)
				.setSignature(signature);
		}
		else if (parsed instanceof org.opensaml.saml.saml2.core.LogoutRequest) {
			result = resolveLogoutRequest(
				(org.opensaml.saml.saml2.core.LogoutRequest) parsed,
				verificationKeys,
				localKeys
			)
				.setSignature(signature);
		}
		else if (parsed instanceof org.opensaml.saml.saml2.core.LogoutResponse) {
			result = resolveLogoutResponse(
				(org.opensaml.saml.saml2.core.LogoutResponse) parsed,
				verificationKeys,
				localKeys
			)
				.setSignature(signature);
		}
		if (result != null) {
			if (result instanceof Saml2ImplementationHolder) {
				((Saml2ImplementationHolder) result).setImplementation(parsed);
				((Saml2ImplementationHolder) result).setOriginalDataRepresentation(new String(
					xml,
					StandardCharsets.UTF_8
				));
			}
			return result;
		}
		throw new Saml2Exception("Deserialization not yet supported for class: " + parsed.getClass());
	}

	@Override
	protected Saml2Signature getValidSignature(Saml2SignableObject saml2Object, List<Saml2KeyData> trustedKeys) {
		if (saml2Object.getImplementation() instanceof SignableSAMLObject) {
			return validateSignature((SignableSAMLObject) saml2Object.getImplementation(), trustedKeys);
		}
		else {
			throw new Saml2SignatureException(
				"Unrecognized object type:" + saml2Object.getImplementation().getClass().getName()
			);
		}
	}

	private Saml2Signature validateSignature(SignableSAMLObject object, List<Saml2KeyData> keys) {
		Saml2Signature result = null;
		if (object.isSigned() && keys != null && !keys.isEmpty()) {
			SignatureException last = null;
			for (Saml2KeyData key : keys) {
				try {
					Credential credential = getCredential(key, getCredentialsResolver(key));
					SignatureValidator.validate(object.getSignature(), credential);
					last = null;
					result = getSignature(object)
						.setValidated(true)
						.setValidatingKey(key);
					break;
				} catch (SignatureException e) {
					last = e;
				}
			}
			if (last != null) {
				throw new Saml2SignatureException(
					"Signature validation against a " + object.getClass().getName() +
						" object failed using " + keys.size() + (keys.size() == 1 ? " key." : " keys."),
					last
				);
			}
		}
		return result;
	}

	private Credential getCredential(Saml2KeyData key, KeyStoreCredentialResolver resolver) {
		try {
			CriteriaSet cs = new CriteriaSet();
			EntityIdCriterion criteria = new EntityIdCriterion(key.getId());
			cs.add(criteria);
			return resolver.resolveSingle(cs);
		} catch (ResolverException e) {
			throw new Saml2KeyException("Can't obtain SP private key", e);
		}
	}

	private KeyStoreCredentialResolver getCredentialsResolver(Saml2KeyData key) {
		KeyStore ks = samlKeyStoreProvider.getKeyStore(key);
		Map<String, String> passwords = hasText(key.getPrivateKey()) ?
			Collections.singletonMap(key.getId(), key.getPassphrase()) :
			Collections.emptyMap();
		KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(
			ks,
			passwords
		);
		return resolver;
	}

	private Saml2Signature getSignature(SignableSAMLObject target) {
		org.opensaml.xmlsec.signature.Signature signature = target.getSignature();
		Saml2Signature result = null;
		if (signature != null && signature instanceof SignatureImpl) {
			SignatureImpl impl = (SignatureImpl) signature;
			try {
				result = new Saml2Signature()
					.setSignatureAlgorithm(Saml2AlgorithmMethod.fromUrn(impl.getSignatureAlgorithm()))
					.setCanonicalizationAlgorithm(Saml2CanonicalizationMethod.fromUrn(impl
						.getCanonicalizationAlgorithm()))
					.setSignatureValue(org.apache.xml.security.utils.Base64.encode(impl.getXMLSignature()
						.getSignatureValue()))
				;
				//TODO extract the digest value
				for (ContentReference ref :
					ofNullable(signature.getContentReferences()).orElse(emptyList())) {
					if (ref instanceof SAMLObjectContentReference) {
						SAMLObjectContentReference sref = (SAMLObjectContentReference) ref;
						result.setDigestAlgorithm(Saml2DigestMethod.fromUrn(sref.getDigestAlgorithm()));
					}
				}

			} catch (XMLSignatureException e) {
				//TODO - ignore for now
			}
		}
		return result;
	}

	private EncryptedAssertion encryptAssertion(org.opensaml.saml.saml2.core.Assertion assertion,
												Saml2KeyData key,
												Saml2KeyEncryptionMethod keyAlgorithm,
												Saml2DataEncryptionMethod dataAlgorithm) {
		Encrypter encrypter = getEncrypter(key, keyAlgorithm, dataAlgorithm);
		try {
			Encrypter.KeyPlacement keyPlacement =
				Encrypter.KeyPlacement.valueOf(
					System.getProperty("spring.security.saml.encrypt.key.placement", "PEER")
				);
			encrypter.setKeyPlacement(keyPlacement);
			return encrypter.encrypt(assertion);
		} catch (EncryptionException e) {
			throw new Saml2Exception("Unable to encrypt assertion.", e);
		}
	}

	private SAMLObject decrypt(EncryptedElementType encrypted, List<Saml2KeyData> keys) {
		DecryptionException last = null;
		for (Saml2KeyData key : keys) {
			Decrypter decrypter = getDecrypter(key);
			try {
				return (SAMLObject) decrypter.decryptData(encrypted.getEncryptedData());
			} catch (DecryptionException e) {
				logger.debug(format("Unable to decrypt element:%s", encrypted), e);
				last = e;
			}
		}
		if (last != null) {
			throw new Saml2KeyException("Unable to decrypt object.", last);
		}
		return null;
	}

	private Encrypter getEncrypter(Saml2KeyData key,
								   Saml2KeyEncryptionMethod keyAlgorithm,
								   Saml2DataEncryptionMethod dataAlgorithm) {
		Credential credential = getCredential(key, getCredentialsResolver(key));

		SecretKey secretKey = generateKeyFromURI(dataAlgorithm);
		BasicCredential dataCredential = new BasicCredential(secretKey);
		DataEncryptionParameters dataEncryptionParameters = new DataEncryptionParameters();
		dataEncryptionParameters.setEncryptionCredential(dataCredential);
		dataEncryptionParameters.setAlgorithm(dataAlgorithm.toString());

		KeyEncryptionParameters keyEncryptionParameters = new KeyEncryptionParameters();
		keyEncryptionParameters.setEncryptionCredential(credential);
		keyEncryptionParameters.setAlgorithm(keyAlgorithm.toString());

		Encrypter encrypter = new Encrypter(dataEncryptionParameters, asList(keyEncryptionParameters));

		return encrypter;
	}

	private static SecretKey generateKeyFromURI(Saml2DataEncryptionMethod algoURI) {
		try {
			String jceAlgorithmName = JCEMapper.getJCEKeyAlgorithmFromURI(algoURI.toString());
			int keyLength = JCEMapper.getKeyLengthFromURI(algoURI.toString());
			return generateKey(jceAlgorithmName, keyLength, null);
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new Saml2Exception(e);
		}
	}

	private Decrypter getDecrypter(Saml2KeyData key) {
		Credential credential = getCredential(key, getCredentialsResolver(key));
		KeyInfoCredentialResolver resolver = new StaticKeyInfoCredentialResolver(credential);
		Decrypter decrypter = new Decrypter(null, resolver, encryptedKeyResolver);
		decrypter.setRootInNewDocument(true);
		return decrypter;
	}

	private XMLObject parse(byte[] xml) {
		try {
			Document document = getParserPool().parse(new ByteArrayInputStream(xml));
			Element element = document.getDocumentElement();
			return getUnmarshallerFactory().getUnmarshaller(element).unmarshall(element);
		} catch (UnmarshallingException | XMLParserException e) {
			throw new Saml2Exception(e);
		}
	}

	private List<? extends Saml2Provider> getSsoProviders(EntityDescriptor descriptor) {
		final List<Saml2SsoProvider> providers = new LinkedList<>();
		for (RoleDescriptor roleDescriptor : descriptor.getRoleDescriptors()) {
			if (roleDescriptor instanceof IDPSSODescriptor || roleDescriptor instanceof SPSSODescriptor) {
				providers.add(getSsoProvider(roleDescriptor));
			}
			else {
				logger.debug("Ignoring unknown metadata descriptor:" + roleDescriptor.getClass().getName());
			}
		}
		return providers;
	}

	private Saml2SsoProvider getSsoProvider(RoleDescriptor descriptor) {
		if (descriptor instanceof SPSSODescriptor) {
			SPSSODescriptor desc = (SPSSODescriptor) descriptor;
			Saml2ServiceProvider provider = new Saml2ServiceProvider();
			provider.setId(desc.getID());
			provider.setValidUntil(desc.getValidUntil());
			if (desc.getCacheDuration() != null) {
				provider.setCacheDuration(toDuration(desc.getCacheDuration()));
			}
			provider.setProtocolSupportEnumeration(desc.getSupportedProtocols());
			provider.setNameIds(getNameIDs(desc.getNameIDFormats()));
			provider.setArtifactResolutionService(getEndpoints(desc.getArtifactResolutionServices()));
			provider.setSingleLogoutService(getEndpoints(desc.getSingleLogoutServices()));
			provider.setManageNameIDService(getEndpoints(desc.getManageNameIDServices()));
			provider.setAuthnRequestsSigned(desc.isAuthnRequestsSigned());
			provider.setWantAssertionsSigned(desc.getWantAssertionsSigned());
			provider.setAssertionConsumerService(getEndpoints(desc.getAssertionConsumerServices()));
			provider.setRequestedAttributes(getRequestAttributes(desc));
			provider.setKeys(getProviderKeys(descriptor));
			provider.setDiscovery(getDiscovery(desc));
			provider.setRequestInitiation(getRequestInitiation(desc));
			//TODO
			//provider.setAttributeConsumingService(getEndpoints(desc.getAttributeConsumingServices()));
			return provider;
		}
		else if (descriptor instanceof IDPSSODescriptor) {
			IDPSSODescriptor desc = (IDPSSODescriptor) descriptor;
			Saml2IdentityProvider provider = new Saml2IdentityProvider();
			provider.setId(desc.getID());
			provider.setValidUntil(desc.getValidUntil());
			if (desc.getCacheDuration() != null) {
				provider.setCacheDuration(toDuration(desc.getCacheDuration()));
			}
			provider.setProtocolSupportEnumeration(desc.getSupportedProtocols());
			provider.setNameIds(getNameIDs(desc.getNameIDFormats()));
			provider.setArtifactResolutionService(getEndpoints(desc.getArtifactResolutionServices()));
			provider.setSingleLogoutService(getEndpoints(desc.getSingleLogoutServices()));
			provider.setManageNameIDService(getEndpoints(desc.getManageNameIDServices()));
			provider.setWantAuthnRequestsSigned(desc.getWantAuthnRequestsSigned());
			provider.setSingleSignOnService(getEndpoints(desc.getSingleSignOnServices()));
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

	private List<Saml2Attribute> getRequestAttributes(SPSSODescriptor desc) {
		List<Saml2Attribute> result = new LinkedList<>();
		if (desc.getDefaultAttributeConsumingService() != null) {
			result.addAll(getRequestedAttributes(desc.getDefaultAttributeConsumingService()
				.getRequestAttributes()));
		}
		else {
			for (AttributeConsumingService s :
				ofNullable(desc.getAttributeConsumingServices()).orElse(emptyList())) {
				if (s != null) {
					//take the first one
					result.addAll(getRequestedAttributes(s.getRequestAttributes()));
					break;
				}
			}
		}
		return result;
	}

	private Saml2Endpoint getRequestInitiation(RoleDescriptor desc) {
		if (desc.getExtensions() == null) {
			return null;
		}
		Saml2Endpoint result = null;
		for (XMLObject obj : desc.getExtensions().getUnknownXMLObjects()) {
			if (obj instanceof RequestInitiator) {
				RequestInitiator req = (RequestInitiator) obj;
				result = new Saml2Endpoint()
					.setIndex(0)
					.setDefault(false)
					.setBinding(Saml2Binding.fromUrn(req.getBinding()))
					.setLocation(req.getLocation())
					.setResponseLocation(req.getResponseLocation());
			}
		}
		return result;
	}

	private Saml2Endpoint getDiscovery(RoleDescriptor desc) {
		if (desc.getExtensions() == null) {
			return null;
		}
		Saml2Endpoint result = null;
		for (XMLObject obj : desc.getExtensions().getUnknownXMLObjects()) {
			if (obj instanceof DiscoveryResponse) {
				DiscoveryResponse resp = (DiscoveryResponse) obj;
				result = new Saml2Endpoint()
					.setDefault(resp.isDefault())
					.setIndex(resp.getIndex())
					.setBinding(Saml2Binding.fromUrn(resp.getBinding()))
					.setLocation(resp.getLocation())
					.setResponseLocation(resp.getResponseLocation());
			}
		}
		return result;
	}

	private List<Saml2KeyData> getProviderKeys(RoleDescriptor descriptor) {
		List<Saml2KeyData> result = new LinkedList<>();
		for (KeyDescriptor desc : ofNullable(descriptor.getKeyDescriptors()).orElse(emptyList())) {
			if (desc != null) {
				result.addAll(getKeyFromDescriptor(desc));
			}
		}
		return result;
	}

	private List<Saml2KeyData> getKeyFromDescriptor(KeyDescriptor desc) {
		List<Saml2KeyData> result = new LinkedList<>();
		if (desc.getKeyInfo() == null) {
			return null;
		}
		Saml2KeyType type =
			desc.getUse() != null ? Saml2KeyType.valueOf(desc.getUse().name()) : Saml2KeyType.UNSPECIFIED;
		int index = 0;
		for (X509Data x509 : ofNullable(desc.getKeyInfo().getX509Datas()).orElse(emptyList())) {
			for (X509Certificate cert : ofNullable(x509.getX509Certificates()).orElse(emptyList())) {
				result.add(new Saml2KeyData(type.getTypeName() + "-" + (index++), null, cert.getValue(), null,
					type
				));
			}
		}

		return result;
	}

	private List<Saml2Endpoint> getEndpoints(
		List<? extends org.opensaml.saml.saml2.metadata.Endpoint>
			services
	) {
		List<Saml2Endpoint> result = new LinkedList<>();
		if (services != null) {
			services
				.stream()
				.forEach(s -> {
						Saml2Endpoint endpoint = new Saml2Endpoint()
							.setBinding(Saml2Binding.fromUrn(s.getBinding()))
							.setLocation(s.getLocation())
							.setResponseLocation(s.getResponseLocation());
						result.add(endpoint);
						if (s instanceof IndexedEndpoint) {
							IndexedEndpoint idxEndpoint = (IndexedEndpoint) s;
							endpoint
								.setIndex(idxEndpoint.getIndex())
								.setDefault(idxEndpoint.isDefault());
						}
					}
				);
		}
		return result;
	}

	private List<Saml2NameId> getNameIDs(List<NameIDFormat> nameIDFormats) {
		List<Saml2NameId> result = new LinkedList<>();
		if (nameIDFormats != null) {
			nameIDFormats.stream()
				.forEach(n -> result.add(Saml2NameId.fromUrn(n.getFormat())));
		}
		return result;
	}

	private org.opensaml.saml.saml2.core.Response internalToXml(Saml2Response response) {
		org.opensaml.saml.saml2.core.Response result = buildSAMLObject(org.opensaml.saml.saml2.core.Response.class);
		result.setConsent(response.getConsent());
		result.setID(ofNullable(response.getId()).orElse("A" + UUID.randomUUID().toString()));
		result.setInResponseTo(response.getInResponseTo());
		result.setVersion(SAMLVersion.VERSION_20);
		result.setIssueInstant(response.getIssueInstant());
		result.setDestination(response.getDestination());
		result.setIssuer(toIssuer(response.getIssuer()));

		if (response.getStatus() == null || response.getStatus().getCode() == null) {
			throw new Saml2Exception("Status cannot be null on a response");
		}
		org.opensaml.saml.saml2.core.Status status = buildSAMLObject(org.opensaml.saml.saml2.core.Status.class);
		org.opensaml.saml.saml2.core.StatusCode code = buildSAMLObject(org.opensaml.saml.saml2.core.StatusCode.class);
		code.setValue(response.getStatus().getCode().toString());
		status.setStatusCode(code);

		if (hasText(response.getStatus().getMessage())) {
			StatusMessage message = buildSAMLObject(StatusMessage.class);
			message.setMessage(response.getStatus().getMessage());
			status.setStatusMessage(message);
		}

		result.setStatus(status);

		for (Saml2Assertion a : ofNullable(response.getAssertions()).orElse(emptyList())) {
			org.opensaml.saml.saml2.core.Assertion osAssertion = internalToXml(a);
			if (a.getEncryptionKey() != null) {
				EncryptedAssertion encryptedAssertion =
					encryptAssertion(osAssertion, a.getEncryptionKey(), a.getKeyAlgorithm(), a.getDataAlgorithm());
				result.getEncryptedAssertions().add(encryptedAssertion);
			}
			else {
				result.getAssertions().add(osAssertion);
			}
		}
		if (response.getSigningKey() != null) {
			signObject(result, response.getSigningKey(), response.getAlgorithm(), response.getDigest());
		}
		return result;
	}

	private EntityDescriptor internalToXml(Saml2Metadata<? extends Saml2Metadata> metadata) {
		EntityDescriptor desc = getEntityDescriptor();
		desc.setEntityID(metadata.getEntityId());
		if (hasText(metadata.getId())) {
			desc.setID(metadata.getId());
		}
		else {
			desc.setID("M" + UUID.randomUUID().toString());
		}
		List<RoleDescriptor> descriptors = getRoleDescriptors(metadata);
		desc.getRoleDescriptors().addAll(descriptors);
		if (metadata.getSigningKey() != null) {
			signObject(desc, metadata.getSigningKey(), metadata.getAlgorithm(), metadata.getDigest());
		}
		return desc;
	}

	private List<RoleDescriptor> getRoleDescriptors(Saml2Metadata<? extends Saml2Metadata> metadata) {
		List<RoleDescriptor> result = new LinkedList<>();
		for (Saml2SsoProvider<? extends Saml2SsoProvider> p : metadata.getSsoProviders()) {
			RoleDescriptor roleDescriptor = null;
			if (p instanceof Saml2ServiceProvider) {
				Saml2ServiceProvider sp = (Saml2ServiceProvider) p;
				SPSSODescriptor descriptor = getSPSSODescriptor();
				roleDescriptor = descriptor;
				descriptor.setAuthnRequestsSigned(sp.isAuthnRequestsSigned());
				descriptor.setWantAssertionsSigned(sp.isWantAssertionsSigned());

				for (Saml2NameId id : p.getNameIds()) {
					descriptor.getNameIDFormats().add(getNameIDFormat(id));
				}

				for (int i = 0; i < sp.getAssertionConsumerService().size(); i++) {
					Saml2Endpoint ep = sp.getAssertionConsumerService().get(i);
					descriptor.getAssertionConsumerServices().add(getAssertionConsumerService(ep, i));
				}
				for (int i = 0; i < sp.getArtifactResolutionService().size(); i++) {
					Saml2Endpoint ep = sp.getArtifactResolutionService().get(i);
					descriptor.getArtifactResolutionServices().add(getArtifactResolutionService(ep, i));
				}
				for (int i = 0; i < sp.getSingleLogoutService().size(); i++) {
					Saml2Endpoint ep = sp.getSingleLogoutService().get(i);
					descriptor.getSingleLogoutServices().add(getSingleLogoutService(ep));
				}
				if (sp.getRequestedAttributes() != null && !sp.getRequestedAttributes().isEmpty()) {
					descriptor
						.getAttributeConsumingServices()
						.add(getAttributeConsumingService(sp.getRequestedAttributes()));
				}

			}
			else if (p instanceof Saml2IdentityProvider) {
				Saml2IdentityProvider idp = (Saml2IdentityProvider) p;
				IDPSSODescriptor descriptor = getIDPSSODescriptor();
				roleDescriptor = descriptor;
				descriptor.setWantAuthnRequestsSigned(idp.getWantAuthnRequestsSigned());
				for (Saml2NameId id : p.getNameIds()) {
					descriptor.getNameIDFormats().add(getNameIDFormat(id));
				}
				for (int i = 0; i < idp.getSingleSignOnService().size(); i++) {
					Saml2Endpoint ep = idp.getSingleSignOnService().get(i);
					descriptor.getSingleSignOnServices().add(getSingleSignOnService(ep, i));
				}
				for (int i = 0; i < p.getSingleLogoutService().size(); i++) {
					Saml2Endpoint ep = p.getSingleLogoutService().get(i);
					descriptor.getSingleLogoutServices().add(getSingleLogoutService(ep));
				}
				for (int i = 0; i < p.getArtifactResolutionService().size(); i++) {
					Saml2Endpoint ep = p.getArtifactResolutionService().get(i);
					descriptor.getArtifactResolutionServices().add(getArtifactResolutionService(ep, i));
				}
			}
			long now = getTime().millis();
			if (p.getCacheDuration() != null) {
				roleDescriptor.setCacheDuration(p.getCacheDuration().getTimeInMillis(new Date(now)));
			}
			roleDescriptor.setValidUntil(p.getValidUntil());
			roleDescriptor.addSupportedProtocol(NS_PROTOCOL);
			roleDescriptor.setID(ofNullable(p.getId()).orElse("RD" + UUID.randomUUID().toString()));

			for (Saml2KeyData key : p.getKeys()) {
				roleDescriptor.getKeyDescriptors().add(getKeyDescriptor(key));
			}

			//md:extensions
			Saml2Endpoint requestInitiation = p.getRequestInitiation();
			Saml2Endpoint discovery = p.getDiscovery();
			if (requestInitiation != null || discovery != null) {
				ExtensionsBuilder extensionsBuilder = (ExtensionsBuilder) getBuilderFactory().getBuilder
					(Extensions.DEFAULT_ELEMENT_NAME);
				roleDescriptor.setExtensions(extensionsBuilder.buildObject());

				if (requestInitiation != null) {
					RequestInitiatorBuilder builder = (RequestInitiatorBuilder) getBuilderFactory().getBuilder
						(RequestInitiator.DEFAULT_ELEMENT_NAME);
					RequestInitiator init = builder.buildObject();
					init.setBinding(requestInitiation.getBinding().toString());
					init.setLocation(requestInitiation.getLocation());
					init.setResponseLocation(requestInitiation.getResponseLocation());
					roleDescriptor.getExtensions().getUnknownXMLObjects().add(init);
				}
				if (discovery != null) {
					DiscoveryResponseBuilder builder = (DiscoveryResponseBuilder) getBuilderFactory().getBuilder
						(DiscoveryResponse.DEFAULT_ELEMENT_NAME);
					DiscoveryResponse response = builder.buildObject(DiscoveryResponse.DEFAULT_ELEMENT_NAME);
					response.setBinding(discovery.getBinding().toString());
					response.setLocation(discovery.getLocation());
					response.setResponseLocation(discovery.getResponseLocation());
					response.setIsDefault(discovery.isDefault());
					response.setIndex(discovery.getIndex());
					roleDescriptor.getExtensions().getUnknownXMLObjects().add(response);
				}
			}
			result.add(roleDescriptor);
		}
		return result;
	}

	private AttributeConsumingService getAttributeConsumingService(List<Saml2Attribute> attributes) {

		AttributeConsumingService service = buildSAMLObject(AttributeConsumingService.class);
		service.setIsDefault(true);
		service.setIndex(0);
		List<RequestedAttribute> attrs = new LinkedList<>();
		for (Saml2Attribute a : attributes) {
			RequestedAttribute ra = buildSAMLObject(RequestedAttribute.class);
			ra.setIsRequired(a.isRequired());
			ra.setFriendlyName(a.getFriendlyName());
			ra.setName(a.getName());
			ra.setNameFormat(a.getNameFormat().toString());
			attrs.add(ra);
		}
		service.getRequestAttributes().addAll(attrs);
		return service;
	}

	private ArtifactResolutionService getArtifactResolutionService(Saml2Endpoint ep, int i) {
		ArtifactResolutionService service = buildSAMLObject(ArtifactResolutionService.class);
		service.setLocation(ep.getLocation());
		service.setBinding(ep.getBinding().toString());
		service.setIndex(i);
		service.setIsDefault(ep.isDefault());
		service.setResponseLocation(ep.getResponseLocation());
		return service;
	}

	private org.opensaml.saml.saml2.core.LogoutResponse internalToXml(Saml2LogoutResponse response) {
		org.opensaml.saml.saml2.core.LogoutResponse result =
			buildSAMLObject(org.opensaml.saml.saml2.core.LogoutResponse.class);
		result.setInResponseTo(response.getInResponseTo());
		result.setID(response.getId());
		result.setIssueInstant(response.getIssueInstant());
		result.setDestination(response.getDestination());

		org.opensaml.saml.saml2.core.Issuer issuer = buildSAMLObject(org.opensaml.saml.saml2.core.Issuer.class);
		issuer.setValue(response.getIssuer().getValue());
		issuer.setNameQualifier(response.getIssuer().getNameQualifier());
		issuer.setSPNameQualifier(response.getIssuer().getSpNameQualifier());
		result.setIssuer(issuer);

		org.opensaml.saml.saml2.core.Status status = buildSAMLObject(org.opensaml.saml.saml2.core.Status.class);
		org.opensaml.saml.saml2.core.StatusCode code = buildSAMLObject(org.opensaml.saml.saml2.core.StatusCode.class);
		code.setValue(response.getStatus().getCode().toString());
		status.setStatusCode(code);
		if (hasText(response.getStatus().getMessage())) {
			StatusMessage message = buildSAMLObject(StatusMessage.class);
			message.setMessage(response.getStatus().getMessage());
			status.setStatusMessage(message);
		}
		result.setStatus(status);

		if (response.getSigningKey() != null) {
			this.signObject(result, response.getSigningKey(), response.getAlgorithm(), response.getDigest());
		}

		return result;
	}

	private org.opensaml.saml.saml2.core.LogoutRequest internalToXml(Saml2LogoutRequest request) {
		org.opensaml.saml.saml2.core.LogoutRequest lr =
			buildSAMLObject(org.opensaml.saml.saml2.core.LogoutRequest.class);
		lr.setDestination(request.getDestination().getLocation());
		lr.setID(request.getId());
		lr.setVersion(SAMLVersion.VERSION_20);
		org.opensaml.saml.saml2.core.Issuer issuer = buildSAMLObject(org.opensaml.saml.saml2.core.Issuer.class);
		issuer.setValue(request.getIssuer().getValue());
		issuer.setNameQualifier(request.getIssuer().getNameQualifier());
		issuer.setSPNameQualifier(request.getIssuer().getSpNameQualifier());
		lr.setIssuer(issuer);
		lr.setIssueInstant(request.getIssueInstant());
		lr.setNotOnOrAfter(request.getNotOnOrAfter());
		NameID nameID = buildSAMLObject(NameID.class);
		nameID.setFormat(request.getNameId().getFormat().toString());
		nameID.setValue(request.getNameId().getValue());
		nameID.setSPNameQualifier(request.getNameId().getSpNameQualifier());
		nameID.setNameQualifier(request.getNameId().getNameQualifier());
		lr.setNameID(nameID);
		if (request.getSigningKey() != null) {
			signObject(lr, request.getSigningKey(), request.getAlgorithm(), request.getDigest());
		}
		return lr;
	}

	private org.opensaml.saml.saml2.core.Assertion internalToXml(Saml2Assertion request) {
		org.opensaml.saml.saml2.core.Assertion a = buildSAMLObject(org.opensaml.saml.saml2.core.Assertion
			.class);
		a.setVersion(SAMLVersion.VERSION_20);
		a.setIssueInstant(request.getIssueInstant());
		a.setID(request.getId());
		org.opensaml.saml.saml2.core.Issuer issuer = buildSAMLObject(org.opensaml.saml.saml2.core.Issuer
			.class);
		issuer.setValue(request.getIssuer().getValue());
		a.setIssuer(issuer);

		Saml2NameIdPrincipal principal = (Saml2NameIdPrincipal) request.getSubject().getPrincipal();

		NameID nid = buildSAMLObject(NameID.class);
		nid.setValue(request.getSubject().getPrincipal().getValue());
		nid.setFormat(principal.getFormat().toString());
		nid.setSPNameQualifier(principal.getSpNameQualifier());

		org.opensaml.saml.saml2.core.SubjectConfirmationData confData =
			buildSAMLObject(org.opensaml.saml.saml2.core.SubjectConfirmationData.class);
		confData.setInResponseTo(request.getSubject()
			.getConfirmations()
			.get(0)
			.getConfirmationData()
			.getInResponseTo());
		confData.setNotBefore(request.getSubject().getConfirmations().get(0).getConfirmationData().getNotBefore());
		confData.setNotOnOrAfter(request.getSubject()
			.getConfirmations()
			.get(0)
			.getConfirmationData()
			.getNotOnOrAfter());
		confData.setRecipient(request.getSubject().getConfirmations().get(0).getConfirmationData().getRecipient());

		org.opensaml.saml.saml2.core.SubjectConfirmation confirmation =
			buildSAMLObject(org.opensaml.saml.saml2.core.SubjectConfirmation.class);
		confirmation.setMethod(request.getSubject().getConfirmations().get(0).getMethod().toString());
		confirmation.setSubjectConfirmationData(confData);

		org.opensaml.saml.saml2.core.Subject subject =
			buildSAMLObject(org.opensaml.saml.saml2.core.Subject.class);
		a.setSubject(subject);
		subject.setNameID(nid);
		subject.getSubjectConfirmations().add(confirmation);

		org.opensaml.saml.saml2.core.Conditions conditions =
			buildSAMLObject(org.opensaml.saml.saml2.core.Conditions.class);
		conditions.setNotBefore(request.getConditions().getNotBefore());
		conditions.setNotOnOrAfter(request.getConditions().getNotOnOrAfter());
		a.setConditions(conditions);

		request.getConditions().getCriteria().forEach(c -> addCondition(conditions, c));


		for (Saml2AuthenticationStatement stmt : request.getAuthenticationStatements()) {
			org.opensaml.saml.saml2.core.AuthnStatement authnStatement =
				buildSAMLObject(org.opensaml.saml.saml2.core.AuthnStatement.class);
			org.opensaml.saml.saml2.core.AuthnContext actx =
				buildSAMLObject(org.opensaml.saml.saml2.core.AuthnContext.class);
			org.opensaml.saml.saml2.core.AuthnContextClassRef aref =
				buildSAMLObject(org.opensaml.saml.saml2.core.AuthnContextClassRef.class);
			Saml2AuthenticationContext authenticationContext = stmt.getAuthenticationContext();
			aref.setAuthnContextClassRef(authenticationContext.getClassReference().toString());
			if (!CollectionUtils.isEmpty(authenticationContext.getAuthenticatingAuthorities())) {
				actx.getAuthenticatingAuthorities()
					.addAll(authenticationContext.getAuthenticatingAuthorities()
						.stream()
						.map(uri -> {
							AuthenticatingAuthority authenticatingAuthority =
								buildSAMLObject(AuthenticatingAuthority.class);
							authenticatingAuthority.setURI(uri);
							return authenticatingAuthority;
						})
						.collect(Collectors.toList()));
			}
			actx.setAuthnContextClassRef(aref);
			authnStatement.setAuthnContext(actx);
			a.getAuthnStatements().add(authnStatement);
			authnStatement.setSessionIndex(stmt.getSessionIndex());
			authnStatement.setSessionNotOnOrAfter(stmt.getSessionNotOnOrAfter());
			authnStatement.setAuthnInstant(stmt.getAuthInstant());
		}

		org.opensaml.saml.saml2.core.AttributeStatement astmt =
			buildSAMLObject(org.opensaml.saml.saml2.core.AttributeStatement.class);
		for (Saml2Attribute attr : request.getAttributes()) {
			org.opensaml.saml.saml2.core.Attribute attribute =
				buildSAMLObject(org.opensaml.saml.saml2.core.Attribute.class);
			attribute.setName(attr.getName());
			attribute.setFriendlyName(attr.getFriendlyName());
			attribute.setNameFormat(attr.getNameFormat().toString());
			attr.getValues().stream().forEach(
				av -> attribute.getAttributeValues().add(objectToXmlObject(av))
			);
			astmt.getAttributes().add(attribute);
		}
		a.getAttributeStatements().add(astmt);

		if (request.getSigningKey() != null) {
			signObject(a, request.getSigningKey(), request.getAlgorithm(), request.getDigest());
		}

		return a;
	}

	private void addCondition(org.opensaml.saml.saml2.core.Conditions conditions, Saml2AssertionCondition c) {
		if (c instanceof Saml2AudienceRestriction) {
			org.opensaml.saml.saml2.core.AudienceRestriction ar =
				buildSAMLObject(org.opensaml.saml.saml2.core.AudienceRestriction.class);
			for (String audience : ((Saml2AudienceRestriction) c).getAudiences()) {
				Audience aud = buildSAMLObject(Audience.class);
				aud.setAudienceURI(audience);
				ar.getAudiences().add(aud);
			}
			conditions.getAudienceRestrictions().add(ar);
		}
		else if (c instanceof Saml2OneTimeUse) {
			org.opensaml.saml.saml2.core.OneTimeUse otu =
				buildSAMLObject(org.opensaml.saml.saml2.core.OneTimeUse.class);
			conditions.getConditions().add(otu);
		}
	}

	private AuthnRequest internalToXml(Saml2AuthenticationRequest request) {
		AuthnRequest auth = buildSAMLObject(AuthnRequest.class);
		auth.setID(request.getId());
		auth.setVersion(SAMLVersion.VERSION_20);
		auth.setIssueInstant(request.getIssueInstant());
		auth.setForceAuthn(request.isForceAuth());
		auth.setIsPassive(request.isPassive());
		auth.setProtocolBinding(request.getBinding().toString());
		// Azure AD as IdP will not accept index if protocol binding or AssertationCustomerServiceURL is set.
		//auth.setAssertionConsumerServiceIndex(request.getAssertionConsumerService().getIndex());
		auth.setAssertionConsumerServiceURL(request.getAssertionConsumerService().getLocation());
		auth.setDestination(request.getDestination().getLocation());
		auth.setNameIDPolicy(getNameIDPolicy(request.getNameIdPolicy()));
		auth.setRequestedAuthnContext(getRequestedAuthenticationContext(request));
		auth.setIssuer(toIssuer(request.getIssuer()));
		if (request.getSigningKey() != null) {
			this.signObject(auth, request.getSigningKey(), request.getAlgorithm(), request.getDigest());
		}
		Saml2Scoping saml2Scoping = request.getScoping();
		if (saml2Scoping != null) {
			Scoping scoping = buildSAMLObject(Scoping.class);
			List<String> idpListValues = saml2Scoping.getIdpList();
			if (!CollectionUtils.isEmpty(idpListValues)) {
				IDPList idpList = buildSAMLObject(IDPList.class);
				List<IDPEntry> idpEntries = idpListValues.stream().map(idpId -> {
					IDPEntry idpEntry = buildSAMLObject(IDPEntry.class);
					idpEntry.setProviderID(idpId);
					return idpEntry;
				}).collect(Collectors.toList());
				idpList.getIDPEntrys().addAll(idpEntries);
				scoping.setIDPList(idpList);
			}
			scoping.setProxyCount(saml2Scoping.getProxyCount());
			List<String> requesterIDs = saml2Scoping.getRequesterIds();
			if (!CollectionUtils.isEmpty(requesterIDs)) {
				List<RequesterID> requesterIDList = requesterIDs.stream().map(id -> {
					RequesterID requesterID = buildSAMLObject(RequesterID.class);
					requesterID.setRequesterID(id);
					return requesterID;
				}).collect(Collectors.toList());
				scoping.getRequesterIDs().addAll(requesterIDList);
			}
			auth.setScoping(scoping);
		}
		return auth;
	}

	private String marshallToXml(XMLObject auth) {
		try {
			Element element = getMarshallerFactory()
				.getMarshaller(auth)
				.marshall(auth);
			return SerializeSupport.nodeToString(element);
		} catch (MarshallingException e) {
			throw new Saml2Exception(e);
		}
	}

	private RequestedAuthnContext getRequestedAuthenticationContext(Saml2AuthenticationRequest request) {
		RequestedAuthnContext result = null;
		if (request.getRequestedAuthenticationContext() != null) {
			result = buildSAMLObject(RequestedAuthnContext.class);
			switch (request.getRequestedAuthenticationContext()) {
				case exact:
					result.setComparison(EXACT);
					break;
				case better:
					result.setComparison(AuthnContextComparisonTypeEnumeration.BETTER);
					break;
				case maximum:
					result.setComparison(AuthnContextComparisonTypeEnumeration.MAXIMUM);
					break;
				case minimum:
					result.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
					break;
				default:
					result.setComparison(EXACT);
					break;
			}
			if (request.getAuthenticationContextClassReference() != null) {
				final AuthnContextClassRef authnContextClassRef = buildSAMLObject(AuthnContextClassRef.class);
				authnContextClassRef.setAuthnContextClassRef(request.getAuthenticationContextClassReference()
					.toString());
				result.getAuthnContextClassRefs().add(authnContextClassRef);
			}
		}
		return result;
	}

	private NameIDPolicy getNameIDPolicy(
		Saml2NameIdPolicy nameIdPolicy
	) {
		NameIDPolicy result = null;
		if (nameIdPolicy != null) {
			result = buildSAMLObject(NameIDPolicy.class);
			result.setAllowCreate(nameIdPolicy.getAllowCreate());
			result.setFormat(nameIdPolicy.getFormat().toString());
			result.setSPNameQualifier(nameIdPolicy.getSpNameQualifier());
		}
		return result;
	}

	private Saml2NameIdPolicy fromNameIDPolicy(NameIDPolicy nameIDPolicy) {
		Saml2NameIdPolicy result = null;
		if (nameIDPolicy != null) {
			result = new Saml2NameIdPolicy()
				.setAllowCreate(nameIDPolicy.getAllowCreate())
				.setFormat(Saml2NameId.fromUrn(nameIDPolicy.getFormat()))
				.setSpNameQualifier(nameIDPolicy.getSPNameQualifier());
		}
		return result;
	}

	private Saml2Scoping fromScoping(Scoping scoping) {
		Saml2Scoping result = null;
		if (scoping != null) {
			IDPList idpList = scoping.getIDPList();
			List<RequesterID> requesterIDs = scoping.getRequesterIDs();
			result = new Saml2Scoping(
				idpList != null ? idpList.getIDPEntrys().stream().map(idpEntry -> idpEntry.getProviderID())
					.collect(Collectors.toList()) : Collections.emptyList(),
				requesterIDs != null ? requesterIDs.stream().map(requesterID -> requesterID.getRequesterID())
					.collect(Collectors.toList()) : Collections.emptyList(),
				scoping.getProxyCount()
			);
		}
		return result;
	}

	private Saml2Response resolveResponse(
		org.opensaml.saml.saml2.core.Response parsed,
		List<Saml2KeyData> verificationKeys,
		List<Saml2KeyData> localKeys
	) {
		Saml2Response result = new Saml2Response()
			.setConsent(parsed.getConsent())
			.setDestination(parsed.getDestination())
			.setId(parsed.getID())
			.setInResponseTo(parsed.getInResponseTo())
			.setIssueInstant(parsed.getIssueInstant())
			.setIssuer(getIssuer(parsed.getIssuer()))
			.setVersion(parsed.getVersion().toString())
			.setStatus(getStatus(parsed.getStatus()))
			.setAssertions(
				parsed.getAssertions().stream().map(
					a -> resolveAssertion(a, verificationKeys, localKeys, false)
				)
					.collect(Collectors.toList())
			);
		if (parsed.getEncryptedAssertions() != null && !parsed.getEncryptedAssertions().isEmpty()) {
			parsed
				.getEncryptedAssertions()
				.stream()
				.forEach(
					a -> result.addAssertion(
						resolveAssertion(
							(org.opensaml.saml.saml2.core.Assertion) decrypt(a, localKeys),
							verificationKeys,
							localKeys,
							true
						)
					)
				);
		}

		return result;

	}

	private Saml2LogoutResponse resolveLogoutResponse(org.opensaml.saml.saml2.core.LogoutResponse response,
													  List<Saml2KeyData> verificationKeys,
													  List<Saml2KeyData> localKeys) {
		Saml2LogoutResponse result = new Saml2LogoutResponse()
			.setId(response.getID())
			.setInResponseTo(response.getInResponseTo())
			.setConsent(response.getConsent())
			.setVersion(response.getVersion().toString())
			.setIssueInstant(response.getIssueInstant())
			.setIssuer(getIssuer(response.getIssuer()))
			.setDestination(response.getDestination())
			.setStatus(getStatus(response.getStatus()));

		return result;
	}

	private Saml2LogoutRequest resolveLogoutRequest(org.opensaml.saml.saml2.core.LogoutRequest request,
													List<Saml2KeyData> verificationKeys,
													List<Saml2KeyData> localKeys) {
		Saml2LogoutRequest result = new Saml2LogoutRequest()
			.setId(request.getID())
			.setConsent(request.getConsent())
			.setVersion(request.getVersion().toString())
			.setNotOnOrAfter(request.getNotOnOrAfter())
			.setIssueInstant(request.getIssueInstant())
			.setReason(Saml2LogoutReason.fromUrn(request.getReason()))
			.setIssuer(getIssuer(request.getIssuer()))
			.setDestination(new Saml2Endpoint().setLocation(request.getDestination()));
		NameID nameID = getNameID(request.getNameID(), request.getEncryptedID(), localKeys);
		result.setNameId(getNameIdPrincipal(nameID));
		return result;
	}

	private Saml2Status getStatus(org.opensaml.saml.saml2.core.Status status) {
		return new Saml2Status()
			.setCode(Saml2StatusCode.fromUrn(status.getStatusCode().getValue()))
			.setMessage(status.getStatusMessage() != null ? status.getStatusMessage().getMessage() : null);
	}

	private Saml2Assertion resolveAssertion(
		org.opensaml.saml.saml2.core.Assertion parsed,
		List<Saml2KeyData> verificationKeys,
		List<Saml2KeyData> localKeys,
		boolean encrypted
	) {
		Saml2Signature signature = null;
		if (!encrypted) {
			signature = validateSignature(parsed, verificationKeys);
		}
		return new Saml2Assertion(encrypted)
			.setSignature(signature)
			.setId(parsed.getID())
			.setIssueInstant(parsed.getIssueInstant())
			.setVersion(parsed.getVersion().toString())
			.setIssuer(getIssuer(parsed.getIssuer()))
			.setSubject(getSubject(parsed.getSubject(), localKeys))
			.setConditions(getConditions(parsed.getConditions()))
			.setAuthenticationStatements(getAuthenticationStatements(parsed.getAuthnStatements()))
			.setAttributes(getAttributes(parsed.getAttributeStatements(), localKeys))
			.setImplementation(parsed)
			;
	}

	private List<Saml2Attribute> getRequestedAttributes(List<RequestedAttribute> attributes) {
		List<Saml2Attribute> result = new LinkedList<>();
		for (RequestedAttribute a : ofNullable(attributes).orElse(emptyList())) {
			result.add(
				new Saml2Attribute()
					.setFriendlyName(a.getFriendlyName())
					.setName(a.getName())
					.setNameFormat(Saml2AttributeNameFormat.fromUrn(a.getNameFormat()))
					.setValues(getJavaValues(a.getAttributeValues()))
					.setRequired(a.isRequired())
			);
		}
		return result;
	}

	private List<Saml2Attribute> getAttributes(
		List<AttributeStatement> attributeStatements, List<Saml2KeyData>
		localKeys
	) {
		List<Saml2Attribute> result = new LinkedList<>();
		for (AttributeStatement stmt : ofNullable(attributeStatements).orElse(emptyList())) {
			for (org.opensaml.saml.saml2.core.Attribute a : ofNullable(stmt.getAttributes()).orElse(emptyList())) {
				result.add(
					new Saml2Attribute()
						.setFriendlyName(a.getFriendlyName())
						.setName(a.getName())
						.setNameFormat(Saml2AttributeNameFormat.fromUrn(a.getNameFormat()))
						.setValues(getJavaValues(a.getAttributeValues()))
				);
			}
			for (EncryptedAttribute encryptedAttribute : ofNullable(stmt.getEncryptedAttributes()).orElse(emptyList())) {
				org.opensaml.saml.saml2.core.Attribute a = (org.opensaml.saml.saml2.core.Attribute) decrypt
					(encryptedAttribute, localKeys);
				result.add(
					new Saml2Attribute()
						.setFriendlyName(a.getFriendlyName())
						.setName(a.getName())
						.setNameFormat(Saml2AttributeNameFormat.fromUrn(a.getNameFormat()))
						.setValues(getJavaValues(a.getAttributeValues()))
				);
			}
		}
		return result;
	}

	private List<Object> getJavaValues(List<XMLObject> attributeValues) {
		List<Object> result = new LinkedList<>();
		for (XMLObject o : ofNullable(attributeValues).orElse(emptyList())) {
			if (o == null) {

			}
			else if (o instanceof XSString) {
				result.add(((XSString) o).getValue());
			}
			else if (o instanceof XSURI) {
				try {
					result.add(new URI(((XSURI) o).getValue()));
				} catch (URISyntaxException e) {
					result.add(((XSURI) o).getValue());
				}
			}
			else if (o instanceof XSBoolean) {
				result.add(((XSBoolean) o).getValue().getValue());
			}
			else if (o instanceof XSDateTime) {
				result.add(((XSDateTime) o).getValue());
			}
			else if (o instanceof XSInteger) {
				result.add(((XSInteger) o).getValue());
			}
			else if (o instanceof XSAny) {
				XSAny xsAny = (XSAny) o;
				String textContent = xsAny.getTextContent();
				if (StringUtils.isEmpty(textContent) && !CollectionUtils.isEmpty(xsAny.getUnknownXMLObjects())) {
					XMLObject xmlObject = xsAny.getUnknownXMLObjects().get(0);
					if (xmlObject instanceof NameIDType) {
						result.add(((NameIDType) xmlObject).getValue());
					}
				}
				else {
					result.add(textContent);
				}
			}
			else {
				//we don't know the type.
				result.add(o);
			}
		}

		return result;
	}

	private List<Saml2AuthenticationStatement> getAuthenticationStatements(
		List<AuthnStatement>
			authnStatements
	) {
		List<Saml2AuthenticationStatement> result = new LinkedList<>();

		for (AuthnStatement s : ofNullable(authnStatements).orElse(emptyList())) {
			AuthnContext authnContext = s.getAuthnContext();
			AuthnContextClassRef authnContextClassRef = authnContext.getAuthnContextClassRef();
			String ref = null;
			if (authnContextClassRef.getAuthnContextClassRef() != null) {
				ref = authnContextClassRef.getAuthnContextClassRef();
			}
			List<AuthenticatingAuthority> authenticatingAuthorities = authnContext.getAuthenticatingAuthorities();
			List<String> authenticatingAuthoritiesUrns = authenticatingAuthorities != null ?
				authenticatingAuthorities
					.stream()
					.map(authority -> authority.getURI()).collect(Collectors.toList()) : null;

			result.add(
				new Saml2AuthenticationStatement()
					.setSessionIndex(s.getSessionIndex())
					.setAuthInstant(s.getAuthnInstant())
					.setSessionNotOnOrAfter(s.getSessionNotOnOrAfter())
					.setAuthenticationContext(
						authnContext != null ?
							new Saml2AuthenticationContext()
								.setClassReference(Saml2AuthenticationContextClassReference.fromUrn(ref))
								.setAuthenticatingAuthorities(authenticatingAuthoritiesUrns)
							: null
					)
			);

		}
		return result;
	}

	private Saml2Conditions getConditions(org.opensaml.saml.saml2.core.Conditions conditions) {
		return new Saml2Conditions()
			.setNotBefore(conditions.getNotBefore())
			.setNotOnOrAfter(conditions.getNotOnOrAfter())
			.setCriteria(getCriteria(conditions.getConditions()));
	}

	private List<Saml2AssertionCondition> getCriteria(List<org.opensaml.saml.saml2.core.Condition> conditions) {
		List<Saml2AssertionCondition> result = new LinkedList<>();
		for (Condition c : conditions) {
			if (c instanceof org.opensaml.saml.saml2.core.AudienceRestriction) {
				org.opensaml.saml.saml2.core.AudienceRestriction aud =
					(org.opensaml.saml.saml2.core.AudienceRestriction) c;
				if (aud.getAudiences() != null) {
					result.add(
						new Saml2AudienceRestriction()
							.setAudiences(
								aud.getAudiences().stream().map(
									a -> a.getAudienceURI()
								).collect(Collectors.toList())
							)
					);
				}
			}
			else if (c instanceof org.opensaml.saml.saml2.core.OneTimeUse) {
				result.add(new Saml2OneTimeUse());
			}
		}
		return result;
	}

	private Saml2Subject getSubject(org.opensaml.saml.saml2.core.Subject subject, List<Saml2KeyData> localKeys) {

		return new Saml2Subject()
			.setPrincipal(getPrincipal(subject, localKeys))
			.setConfirmations(getConfirmations(subject.getSubjectConfirmations(), localKeys))
			;
	}

	private List<Saml2SubjectConfirmation> getConfirmations(
		List<org.opensaml.saml.saml2.core
			.SubjectConfirmation> subjectConfirmations, List<Saml2KeyData> localKeys
	) {
		List<Saml2SubjectConfirmation> result = new LinkedList<>();
		for (org.opensaml.saml.saml2.core.SubjectConfirmation s : subjectConfirmations) {
			NameID nameID = getNameID(s.getNameID(), s.getEncryptedID(), localKeys);
			result.add(
				new Saml2SubjectConfirmation()
					.setNameId(nameID != null ? nameID.getValue() : null)
					.setFormat(nameID != null ? Saml2NameId.fromUrn(nameID.getFormat()) : null)
					.setMethod(Saml2SubjectConfirmationMethod.fromUrn(s.getMethod()))
					.setConfirmationData(
						new Saml2SubjectConfirmationData()
							.setRecipient(s.getSubjectConfirmationData().getRecipient())
							.setNotOnOrAfter(s.getSubjectConfirmationData().getNotOnOrAfter())
							.setNotBefore(s.getSubjectConfirmationData().getNotBefore())
							.setInResponseTo(s.getSubjectConfirmationData().getInResponseTo())
					)
			);
		}
		return result;
	}

	private NameID getNameID(NameID id,
							 EncryptedID eid,
							 List<Saml2KeyData> localKeys) {
		NameID result = id;
		if (result == null && eid != null && eid.getEncryptedData() != null) {
			result = (NameID) decrypt(eid, localKeys);
		}
		return result;
	}

	private Saml2NameIdPrincipal getPrincipal(org.opensaml.saml.saml2.core.Subject subject,
											  List<Saml2KeyData> localKeys) {
		NameID p =
			getNameID(
				subject.getNameID(),
				subject.getEncryptedID(),
				localKeys
			);
		if (p != null) {
			return getNameIdPrincipal(p);
		}
		else {
			throw new UnsupportedOperationException("Currently only supporting NameID subject principals");
		}
	}

	private Saml2NameIdPrincipal getNameIdPrincipal(NameID p) {
		return new Saml2NameIdPrincipal()
			.setSpNameQualifier(p.getSPNameQualifier())
			.setNameQualifier(p.getNameQualifier())
			.setFormat(Saml2NameId.fromUrn(p.getFormat()))
			.setSpProvidedId(p.getSPProvidedID())
			.setValue(p.getValue());
	}

	private org.opensaml.saml.saml2.core.Issuer toIssuer(Saml2Issuer issuer) {
		org.opensaml.saml.saml2.core.Issuer result =
			buildSAMLObject(org.opensaml.saml.saml2.core.Issuer.class);
		result.setValue(issuer.getValue());
		if (issuer.getFormat() != null) {
			result.setFormat(issuer.getFormat().toString());
		}
		result.setSPNameQualifier(issuer.getSpNameQualifier());
		result.setNameQualifier(issuer.getNameQualifier());
		return result;
	}

	private Saml2Issuer getIssuer(org.opensaml.saml.saml2.core.Issuer issuer) {
		return issuer == null ? null :
			new Saml2Issuer()
				.setValue(issuer.getValue())
				.setFormat(Saml2NameId.fromUrn(issuer.getFormat()))
				.setSpNameQualifier(issuer.getSPNameQualifier())
				.setNameQualifier(issuer.getNameQualifier());
	}

	private Saml2AuthenticationRequest resolveAuthenticationRequest(AuthnRequest parsed) {
		AuthnRequest request = parsed;
		Saml2AuthenticationRequest result = new Saml2AuthenticationRequest()
			.setBinding(Saml2Binding.fromUrn(request.getProtocolBinding()))
			.setAssertionConsumerService(
				getEndpoint(
					request.getAssertionConsumerServiceURL(),
					Saml2Binding.fromUrn(request.getProtocolBinding()),
					ofNullable(request.getAssertionConsumerServiceIndex()).orElse(-1),
					false
				)
			)
			.setDestination(
				getEndpoint(
					request.getDestination(),
					Saml2Binding.fromUrn(request.getProtocolBinding()),
					-1,
					false
				)
			)
			.setIssuer(getIssuer(request.getIssuer()))
			.setForceAuth(request.isForceAuthn())
			.setPassive(request.isPassive())
			.setId(request.getID())
			.setIssueInstant(request.getIssueInstant())
			.setVersion(request.getVersion().toString())
			.setRequestedAuthenticationContext(getRequestedAuthenticationContext(request))
			.setAuthenticationContextClassReference(getAuthenticationContextClassReference(request))
			.setNameIdPolicy(fromNameIDPolicy(request.getNameIDPolicy()))
			.setScoping(fromScoping(request.getScoping()));

		return result;
	}

	private Saml2AuthenticationContextClassReference getAuthenticationContextClassReference(AuthnRequest request) {
		Saml2AuthenticationContextClassReference result = null;
		final RequestedAuthnContext context = request.getRequestedAuthnContext();
		if (context != null && !CollectionUtils.isEmpty(context.getAuthnContextClassRefs())) {
			final String urn = context.getAuthnContextClassRefs().get(0).getAuthnContextClassRef();
			result = Saml2AuthenticationContextClassReference.fromUrn(urn);
		}
		return result;
	}

	private Saml2RequestedAuthenticationContext getRequestedAuthenticationContext(AuthnRequest request) {
		Saml2RequestedAuthenticationContext result = null;

		if (request.getRequestedAuthnContext() != null) {
			AuthnContextComparisonTypeEnumeration comparison = request.getRequestedAuthnContext().getComparison();
			if (null != comparison) {
				result = Saml2RequestedAuthenticationContext.valueOf(comparison.toString());
			}
		}
		return result;
	}

	private Saml2Metadata resolveMetadata(EntitiesDescriptor parsed,
										  List<Saml2KeyData> verificationKeys,
										  List<Saml2KeyData> localKeys) {
		Saml2Metadata result = null, current = null;
		for (EntityDescriptor desc : parsed.getEntityDescriptors()) {
			if (result == null) {
				result = resolveMetadata(desc);
				current = result;
			}
			else {
				Saml2Metadata m = resolveMetadata(desc);
				current.setNext(m);
				current = m;
			}
			Saml2Signature signature = validateSignature(desc, verificationKeys);
			current.setSignature(signature);
		}
		return result;
	}

	private Saml2Metadata resolveMetadata(EntityDescriptor parsed) {
		EntityDescriptor descriptor = parsed;
		List<? extends Saml2Provider> ssoProviders = getSsoProviders(descriptor);
		Saml2Metadata desc = getMetadata(ssoProviders);
		long duration = descriptor.getCacheDuration() != null ? descriptor.getCacheDuration() : -1;
		desc.setCacheDuration(toDuration(duration));
		desc.setEntityId(descriptor.getEntityID());
		if (isUrl(desc.getEntityId())) {
			desc.setEntityAlias(getHostFromUrl(desc.getEntityId()));
		}
		else {
			desc.setEntityAlias(desc.getEntityId());
		}

		desc.setId(descriptor.getID());
		desc.setValidUntil(descriptor.getValidUntil());
		return desc;
	}

	private Saml2Metadata getMetadata(List<? extends Saml2Provider> ssoProviders) {
		Saml2Metadata result = determineMetadataType(ssoProviders);
		result.setProviders(ssoProviders);
		return result;
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

	private XMLObject objectToXmlObject(Object o) {
		if (o == null) {
			return null;
		}
		else if (o instanceof String) {
			XSStringBuilder builder = (XSStringBuilder) getBuilderFactory().getBuilder(XSString.TYPE_NAME);
			XSString s = builder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
			s.setValue((String) o);
			return s;
		}
		else if (o instanceof URI || o instanceof URL) {
			XSURIBuilder builder = (XSURIBuilder) getBuilderFactory().getBuilder(XSURI.TYPE_NAME);
			XSURI uri = builder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSURI.TYPE_NAME);
			uri.setValue(o.toString());
			return uri;
		}
		else if (o instanceof Boolean) {
			XSBooleanBuilder builder = (XSBooleanBuilder) getBuilderFactory().getBuilder(XSBoolean.TYPE_NAME);
			XSBoolean b = builder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSBoolean.TYPE_NAME);
			XSBooleanValue v = XSBooleanValue.valueOf(o.toString());
			b.setValue(v);
			return b;
		}
		else if (o instanceof DateTime) {
			XSDateTimeBuilder builder = (XSDateTimeBuilder) getBuilderFactory().getBuilder(XSDateTime.TYPE_NAME);
			XSDateTime dt = builder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSDateTime.TYPE_NAME);
			dt.setValue((DateTime) o);
			return dt;
		}
		else if (o instanceof Integer) {
			XSIntegerBuilder builder = (XSIntegerBuilder) getBuilderFactory().getBuilder(XSInteger.TYPE_NAME);
			XSInteger i = builder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSInteger.TYPE_NAME);
			i.setValue(((Integer) o).intValue());
			return i;
		}
		else {
			XSAnyBuilder builder = (XSAnyBuilder) getBuilderFactory().getBuilder(XSAny.TYPE_NAME);
			XSAny any = builder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSAny.TYPE_NAME);
			any.setTextContent(o.toString());
			return any;
		}
	}

	private String xmlObjectToString(XMLObject o) {
		String toMatch = null;
		if (o instanceof XSString) {
			toMatch = ((XSString) o).getValue();
		}
		else if (o instanceof XSURI) {
			toMatch = ((XSURI) o).getValue();
		}
		else if (o instanceof XSBoolean) {
			toMatch = ((XSBoolean) o).getValue().getValue() ? "1" : "0";
		}
		else if (o instanceof XSInteger) {
			toMatch = ((XSInteger) o).getValue().toString();
		}
		else if (o instanceof XSDateTime) {
			final DateTime dt = ((XSDateTime) o).getValue();
			if (dt != null) {
				toMatch = ((XSDateTime) o).getDateTimeFormatter().print(dt);
			}
		}
		else if (o instanceof XSBase64Binary) {
			toMatch = ((XSBase64Binary) o).getValue();
		}
		else if (o instanceof XSAny) {
			final XSAny wc = (XSAny) o;
			if (wc.getUnknownAttributes().isEmpty() && wc.getUnknownXMLObjects().isEmpty()) {
				toMatch = wc.getTextContent();
			}
		}
		if (toMatch != null) {
			return toMatch;
		}
		return null;
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

	private NameIDFormat getNameIDFormat(Saml2NameId nameId) {
		SAMLObjectBuilder<NameIDFormat> builder =
			(SAMLObjectBuilder<NameIDFormat>) getBuilderFactory().getBuilder(NameIDFormat.DEFAULT_ELEMENT_NAME);
		NameIDFormat format = builder.buildObject();
		format.setFormat(nameId.toString());
		return format;
	}

	private SingleSignOnService getSingleSignOnService(Saml2Endpoint endpoint, int index) {
		SAMLObjectBuilder<SingleSignOnService> builder =
			(SAMLObjectBuilder<SingleSignOnService>) getBuilderFactory()
				.getBuilder(SingleSignOnService.DEFAULT_ELEMENT_NAME);
		SingleSignOnService sso = builder.buildObject();
		sso.setLocation(endpoint.getLocation());
		sso.setBinding(endpoint.getBinding().toString());
		return sso;
	}

	private AssertionConsumerService getAssertionConsumerService(Saml2Endpoint endpoint, int index) {
		SAMLObjectBuilder<AssertionConsumerService> builder =
			(SAMLObjectBuilder<AssertionConsumerService>) getBuilderFactory()
				.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
		AssertionConsumerService consumer = builder.buildObject();
		consumer.setLocation(endpoint.getLocation());
		consumer.setBinding(endpoint.getBinding().toString());
		consumer.setIsDefault(endpoint.isDefault());
		consumer.setIndex(index);
		return consumer;
	}

	private SingleLogoutService getSingleLogoutService(Saml2Endpoint endpoint) {
		SAMLObjectBuilder<SingleLogoutService> builder =
			(SAMLObjectBuilder<SingleLogoutService>) getBuilderFactory()
				.getBuilder(SingleLogoutService.DEFAULT_ELEMENT_NAME);
		SingleLogoutService service = builder.buildObject();
		service.setBinding(endpoint.getBinding().toString());
		service.setLocation(endpoint.getLocation());
		return service;
	}

	private KeyDescriptor getKeyDescriptor(Saml2KeyData key) {
		SAMLObjectBuilder<KeyDescriptor> builder =
			(SAMLObjectBuilder<KeyDescriptor>) getBuilderFactory()
				.getBuilder(KeyDescriptor.DEFAULT_ELEMENT_NAME);
		KeyDescriptor descriptor = builder.buildObject();

		KeyStoreCredentialResolver resolver = getCredentialsResolver(key);
		Credential credential = getCredential(key, resolver);
		try {
			KeyInfo info = getKeyInfoGenerator(credential).generate(credential);
			descriptor.setKeyInfo(info);
			if (key.getType() != null) {
				descriptor.setUse(UsageType.valueOf(key.getType().toString()));
			}
			else {
				descriptor.setUse(UsageType.SIGNING);
			}
			return descriptor;
		} catch (SecurityException e) {
			throw new Saml2KeyException(e);
		}
	}

	private KeyInfoGenerator getKeyInfoGenerator(Credential credential) {
		NamedKeyInfoGeneratorManager manager = DefaultSecurityConfigurationBootstrap
			.buildBasicKeyInfoGeneratorManager();
		return manager.getDefaultManager().getFactory(credential).newInstance();
	}

	private void signObject(SignableSAMLObject signable,
							Saml2KeyData key,
							Saml2AlgorithmMethod algorithm,
							Saml2DigestMethod digest) {

		KeyStoreCredentialResolver resolver = getCredentialsResolver(key);
		Credential credential = getCredential(key, resolver);

		XMLObjectBuilder<org.opensaml.xmlsec.signature.Signature> signatureBuilder =
			(XMLObjectBuilder<org.opensaml.xmlsec.signature.Signature>) getBuilderFactory()
				.getBuilder(org.opensaml.xmlsec.signature.Signature.DEFAULT_ELEMENT_NAME);
		org.opensaml.xmlsec.signature.Signature signature = signatureBuilder.buildObject(org.opensaml.xmlsec
			.signature.Signature.DEFAULT_ELEMENT_NAME);

		signable.setSignature(signature);

		SignatureSigningParameters parameters = new SignatureSigningParameters();
		parameters.setSigningCredential(credential);
		parameters.setKeyInfoGenerator(getKeyInfoGenerator(credential));
		parameters.setSignatureAlgorithm(algorithm.toString());
		parameters.setSignatureReferenceDigestMethod(digest.toString());
		parameters.setSignatureCanonicalizationAlgorithm(
			Saml2CanonicalizationMethod.ALGO_ID_C14N_EXCL_OMIT_COMMENTS.toString()
		);

		try {
			SignatureSupport.prepareSignatureParams(signature, parameters);
			Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(signable);
			marshaller.marshall(signable);
			Signer.signObject(signature);
		} catch (SecurityException | MarshallingException | SignatureException e) {
			throw new Saml2KeyException(e);
		}
	}

	private <T> T buildSAMLObject(final Class<T> clazz) {
		try {
			QName defaultElementName = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
			return (T) getBuilderFactory().getBuilder(defaultElementName).buildObject(defaultElementName);
		} catch (IllegalAccessException e) {
			throw new Saml2Exception("Could not create SAML object", e);
		} catch (NoSuchFieldException e) {
			throw new Saml2Exception("Could not create SAML object", e);
		}
	}

}
