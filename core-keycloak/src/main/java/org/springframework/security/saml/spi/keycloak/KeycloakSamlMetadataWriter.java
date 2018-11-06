/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.springframework.security.saml.spi.keycloak;

import java.util.List;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamWriter;

import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.dom.saml.v2.metadata.AttributeConsumingServiceType;
import org.keycloak.dom.saml.v2.metadata.EndpointType;
import org.keycloak.dom.saml.v2.metadata.IDPSSODescriptorType;
import org.keycloak.dom.saml.v2.metadata.IndexedEndpointType;
import org.keycloak.dom.saml.v2.metadata.KeyDescriptorType;
import org.keycloak.dom.saml.v2.metadata.SPSSODescriptorType;
import org.keycloak.saml.common.constants.JBossSAMLConstants;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.StaxUtil;
import org.keycloak.saml.processing.core.saml.v2.writers.SAMLMetadataWriter;

import static org.springframework.util.StringUtils.hasText;

public class KeycloakSamlMetadataWriter extends SAMLMetadataWriter {
	private final String METADATA_PREFIX = "md";

	public KeycloakSamlMetadataWriter(XMLStreamWriter writer) {
		super(writer);
	}

	public void write(SPSSODescriptorType spSSODescriptor) throws ProcessingException {
		StaxUtil.writeStartElement(writer, METADATA_PREFIX, JBossSAMLConstants.SP_SSO_DESCRIPTOR.get(), JBossSAMLURIConstants.METADATA_NSURI.get());
		StaxUtil.writeAttribute(writer, new QName(JBossSAMLConstants.PROTOCOL_SUPPORT_ENUMERATION.get()), spSSODescriptor
			.getProtocolSupportEnumeration().get(0));

		// Write the attributes
		if (hasText(spSSODescriptor.getID())) {
			StaxUtil.writeAttribute(
				writer,
				new QName(JBossSAMLConstants.ID.get()),
				spSSODescriptor.getID()
			);
		}

		Boolean authnSigned = spSSODescriptor.isAuthnRequestsSigned();
		if (authnSigned != null) {
			StaxUtil.writeAttribute(writer, new QName(JBossSAMLConstants.AUTHN_REQUESTS_SIGNED.get()),
				authnSigned.toString());
		}
		Boolean wantAssertionsSigned = spSSODescriptor.isWantAssertionsSigned();
		if (wantAssertionsSigned != null) {
			StaxUtil.writeAttribute(writer, new QName(JBossSAMLConstants.WANT_ASSERTIONS_SIGNED.get()),
				wantAssertionsSigned.toString());
		}

		// Get the key descriptors
		List<KeyDescriptorType> keyDescriptors = spSSODescriptor.getKeyDescriptor();
		for (KeyDescriptorType keyDescriptor : keyDescriptors) {
			writeKeyDescriptor(keyDescriptor);
		}

		List<EndpointType> sloServices = spSSODescriptor.getSingleLogoutService();
		for (EndpointType endpoint : sloServices) {
			writeSingleLogoutService(endpoint);
		}

		List<IndexedEndpointType> artifactResolutions = spSSODescriptor.getArtifactResolutionService();
		for (IndexedEndpointType artifactResolution : artifactResolutions) {
			writeArtifactResolutionService(artifactResolution);
		}

		List<String> nameIDFormats = spSSODescriptor.getNameIDFormat();
		for (String nameIDFormat : nameIDFormats) {
			writeNameIDFormat(nameIDFormat);
		}

		List<IndexedEndpointType> assertionConsumers = spSSODescriptor.getAssertionConsumerService();
		for (IndexedEndpointType assertionConsumer : assertionConsumers) {
			writeAssertionConsumerService(assertionConsumer);
		}

		List<AttributeConsumingServiceType> attributeConsumers = spSSODescriptor.getAttributeConsumingService();
		for (AttributeConsumingServiceType attributeConsumer : attributeConsumers) {
			writeAttributeConsumingService(attributeConsumer);
		}

		StaxUtil.writeEndElement(writer);
		StaxUtil.flush(writer);
	}

	public void write(IDPSSODescriptorType idpSSODescriptor) throws ProcessingException {
		if (idpSSODescriptor == null)
			throw new ProcessingException(logger.nullArgumentError("IDPSSODescriptorType"));

		StaxUtil.writeStartElement(writer, METADATA_PREFIX, JBossSAMLConstants.IDP_SSO_DESCRIPTOR.get(), JBossSAMLURIConstants.METADATA_NSURI.get());

		if (hasText(idpSSODescriptor.getID())) {
			StaxUtil.writeAttribute(
				writer,
				new QName(JBossSAMLConstants.ID.get()),
				idpSSODescriptor.getID()
			);
		}

		Boolean wantsAuthnRequestsSigned = idpSSODescriptor.isWantAuthnRequestsSigned();
		if (wantsAuthnRequestsSigned != null) {
			StaxUtil.writeAttribute(writer, new QName(JBossSAMLConstants.WANT_AUTHN_REQUESTS_SIGNED.get()),
				wantsAuthnRequestsSigned.toString());
		}
		writeProtocolSupportEnumeration(idpSSODescriptor.getProtocolSupportEnumeration());

		List<IndexedEndpointType> artifactResolutionServices = idpSSODescriptor.getArtifactResolutionService();
		for (IndexedEndpointType indexedEndpoint : artifactResolutionServices) {
			writeArtifactResolutionService(indexedEndpoint);
		}

		List<EndpointType> sloServices = idpSSODescriptor.getSingleLogoutService();
		for (EndpointType endpoint : sloServices) {
			writeSingleLogoutService(endpoint);
		}

		List<EndpointType> ssoServices = idpSSODescriptor.getSingleSignOnService();
		for (EndpointType endpoint : ssoServices) {
			writeSingleSignOnService(endpoint);
		}

		List<String> nameIDFormats = idpSSODescriptor.getNameIDFormat();
		for (String nameIDFormat : nameIDFormats) {
			writeNameIDFormat(nameIDFormat);
		}

		List<AttributeType> attributes = idpSSODescriptor.getAttribute();
		for (AttributeType attribType : attributes) {
			write(attribType);
		}

		StaxUtil.writeEndElement(writer);
		StaxUtil.flush(writer);
	}

	private void writeNameIDFormat(String nameIDFormat) throws ProcessingException {
		StaxUtil.writeStartElement(writer, METADATA_PREFIX, JBossSAMLConstants.NAMEID_FORMAT.get(), JBossSAMLURIConstants.METADATA_NSURI.get());

		StaxUtil.writeCharacters(writer, nameIDFormat);
		StaxUtil.writeEndElement(writer);
	}

	private void writeProtocolSupportEnumeration(List<String> protoEnum) throws ProcessingException {
		if (protoEnum.size() > 0) {
			StringBuilder sb = new StringBuilder();
			for (String str : protoEnum) {
				sb.append(str).append(" ");
			}

			StaxUtil.writeAttribute(writer, new QName(JBossSAMLConstants.PROTOCOL_SUPPORT_ENUMERATION.get()), sb.toString()
				.trim());
		}
	}
}
