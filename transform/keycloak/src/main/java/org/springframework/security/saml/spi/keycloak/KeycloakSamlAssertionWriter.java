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

package org.springframework.security.saml.spi.keycloak;

import java.net.URI;
import java.util.List;
import java.util.Set;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamWriter;

import org.joda.time.DateTime;
import org.keycloak.dom.saml.v2.assertion.AdviceType;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AudienceRestrictionType;
import org.keycloak.dom.saml.v2.assertion.AuthnContextType;
import org.keycloak.dom.saml.v2.assertion.AuthnStatementType;
import org.keycloak.dom.saml.v2.assertion.BaseIDAbstractType;
import org.keycloak.dom.saml.v2.assertion.ConditionAbstractType;
import org.keycloak.dom.saml.v2.assertion.ConditionsType;
import org.keycloak.dom.saml.v2.assertion.EncryptedElementType;
import org.keycloak.dom.saml.v2.assertion.KeyInfoConfirmationDataType;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.assertion.OneTimeUseType;
import org.keycloak.dom.saml.v2.assertion.StatementAbstractType;
import org.keycloak.dom.saml.v2.assertion.SubjectConfirmationDataType;
import org.keycloak.dom.saml.v2.assertion.SubjectConfirmationType;
import org.keycloak.dom.saml.v2.assertion.SubjectType;
import org.keycloak.dom.xmlsec.w3.xmldsig.KeyInfoType;
import org.keycloak.saml.common.constants.JBossSAMLConstants;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.StaxUtil;
import org.keycloak.saml.common.util.StringUtil;
import org.keycloak.saml.processing.core.saml.v2.util.StaxWriterUtil;
import org.keycloak.saml.processing.core.saml.v2.writers.SAMLAssertionWriter;
import org.w3c.dom.Element;

import static org.keycloak.saml.common.constants.JBossSAMLURIConstants.ASSERTION_NSURI;
import static org.springframework.security.saml.util.DateUtils.toZuluTime;

public class KeycloakSamlAssertionWriter extends SAMLAssertionWriter {
	public KeycloakSamlAssertionWriter(XMLStreamWriter writer) {
		super(writer);
	}

	@Override
	public void write(AssertionType assertion, boolean forceWriteDsigNamespace) throws ProcessingException {
		Element sig = assertion.getSignature();

		StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.ASSERTION.get(), ASSERTION_NSURI.get());
		StaxUtil.writeNameSpace(writer, ASSERTION_PREFIX, ASSERTION_NSURI.get());
		if (forceWriteDsigNamespace && sig != null && sig.getPrefix() != null && ! sig.hasAttribute("xmlns:" + sig.getPrefix())) {
			StaxUtil.writeNameSpace(writer, sig.getPrefix(), XMLSignature.XMLNS);
		}
		StaxUtil.writeDefaultNameSpace(writer, ASSERTION_NSURI.get());

		// Attributes
		StaxUtil.writeAttribute(writer, JBossSAMLConstants.ID.get(), assertion.getID());
		StaxUtil.writeAttribute(writer, JBossSAMLConstants.VERSION.get(), assertion.getVersion());
		DateTime issueInstant = new DateTime(assertion.getIssueInstant().toGregorianCalendar().toInstant().toEpochMilli());
		StaxUtil.writeAttribute(writer, JBossSAMLConstants.ISSUE_INSTANT.get(), toZuluTime(issueInstant));

		NameIDType issuer = assertion.getIssuer();
		if (issuer != null)
			write(issuer, new QName(ASSERTION_NSURI.get(), JBossSAMLConstants.ISSUER.get(), ASSERTION_PREFIX));

		if (sig != null)
			StaxUtil.writeDOMElement(writer, sig);

		SubjectType subject = assertion.getSubject();
		if (subject != null) {
			write(subject);
		}

		ConditionsType conditions = assertion.getConditions();
		if (conditions != null) {
			StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.CONDITIONS.get(), ASSERTION_NSURI.get());

			if (conditions.getNotBefore() != null) {
				DateTime notBefore = new DateTime(
					conditions.getNotBefore().toGregorianCalendar().toInstant().toEpochMilli()
				);
				StaxUtil.writeAttribute(writer, JBossSAMLConstants.NOT_BEFORE.get(), toZuluTime(notBefore));
			}

			if (conditions.getNotOnOrAfter() != null) {
				DateTime notOnOrAfter = new DateTime(
					conditions.getNotOnOrAfter().toGregorianCalendar().toInstant().toEpochMilli()
				);
				StaxUtil.writeAttribute(writer, JBossSAMLConstants.NOT_ON_OR_AFTER.get(), toZuluTime(notOnOrAfter));
			}

			List<ConditionAbstractType> typeOfConditions = conditions.getConditions();
			if (typeOfConditions != null) {
				for (ConditionAbstractType typeCondition : typeOfConditions) {
					if (typeCondition instanceof AudienceRestrictionType) {
						AudienceRestrictionType art = (AudienceRestrictionType) typeCondition;
						StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.AUDIENCE_RESTRICTION.get(),
							ASSERTION_NSURI.get());
						List<URI> audiences = art.getAudience();
						if (audiences != null) {
							for (URI audience : audiences) {
								StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.AUDIENCE.get(),
									ASSERTION_NSURI.get());
								StaxUtil.writeCharacters(writer, audience.toString());
								StaxUtil.writeEndElement(writer);
							}
						}

						StaxUtil.writeEndElement(writer);
					}
					if (typeCondition instanceof OneTimeUseType) {
						StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.ONE_TIME_USE.get(),
							ASSERTION_NSURI.get());
						StaxUtil.writeEndElement(writer);
					}
				}
			}

			StaxUtil.writeEndElement(writer);
		}

		AdviceType advice = assertion.getAdvice();
		if (advice != null)
			throw logger.notImplementedYet("Advice");

		Set<StatementAbstractType> statements = assertion.getStatements();
		if (statements != null) {
			for (StatementAbstractType statement : statements) {
				if (statement instanceof AuthnStatementType) {
					write((AuthnStatementType) statement, false);
				} else if (statement instanceof AttributeStatementType) {
					write((AttributeStatementType) statement);
				} else
					throw logger.writerUnknownTypeError(statement.getClass().getName());
			}
		}

		StaxUtil.writeEndElement(writer);
		StaxUtil.flush(writer);
	}

	@Override
	public void write(AuthnStatementType authnStatement, boolean includeNamespace) throws ProcessingException {
		StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.AUTHN_STATEMENT.get(), ASSERTION_NSURI.get());
		if (includeNamespace) {
			StaxUtil.writeNameSpace(writer, ASSERTION_PREFIX, ASSERTION_NSURI.get());
			StaxUtil.writeDefaultNameSpace(writer, ASSERTION_NSURI.get());
		}

		XMLGregorianCalendar authnInstant = authnStatement.getAuthnInstant();
		if (authnInstant != null) {
			DateTime authnInstantTime = new DateTime(authnInstant.toGregorianCalendar().toInstant().toEpochMilli());
			StaxUtil.writeAttribute(writer, JBossSAMLConstants.AUTHN_INSTANT.get(), toZuluTime(authnInstantTime));
		}

		String sessionIndex = authnStatement.getSessionIndex();

		if (sessionIndex != null) {
			StaxUtil.writeAttribute(writer, JBossSAMLConstants.SESSION_INDEX.get(), sessionIndex);
		}

		AuthnContextType authnContext = authnStatement.getAuthnContext();
		if (authnContext != null)
			write(authnContext);

		StaxUtil.writeEndElement(writer);
		StaxUtil.flush(writer);
	}

	@Override
	public void write(SubjectType subject) throws ProcessingException {
		StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.SUBJECT.get(), ASSERTION_NSURI.get());

		SubjectType.STSubType subType = subject.getSubType();
		if (subType != null) {
			BaseIDAbstractType baseID = subType.getBaseID();
			if (baseID instanceof NameIDType) {
				NameIDType nameIDType = (NameIDType) baseID;
				write(nameIDType, new QName(ASSERTION_NSURI.get(), JBossSAMLConstants.NAMEID.get(), ASSERTION_PREFIX));
			}
			EncryptedElementType enc = subType.getEncryptedID();
			if (enc != null)
				throw new RuntimeException("NYI");
			List<SubjectConfirmationType> confirmations = subType.getConfirmation();
			if (confirmations != null) {
				for (SubjectConfirmationType confirmation : confirmations) {
					write(confirmation);
				}
			}
		}
		List<SubjectConfirmationType> subjectConfirmations = subject.getConfirmation();
		if (subjectConfirmations != null) {
			for (SubjectConfirmationType subjectConfirmationType : subjectConfirmations) {
				write(subjectConfirmationType);
			}
		}

		StaxUtil.writeEndElement(writer);
		StaxUtil.flush(writer);
	}

	private void write(SubjectConfirmationType subjectConfirmationType) throws ProcessingException {
		StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.SUBJECT_CONFIRMATION.get(),
			ASSERTION_NSURI.get());

		StaxUtil.writeAttribute(writer, JBossSAMLConstants.METHOD.get(), subjectConfirmationType.getMethod());

		BaseIDAbstractType baseID = subjectConfirmationType.getBaseID();
		if (baseID != null) {
			write(baseID);
		}
		NameIDType nameIDType = subjectConfirmationType.getNameID();
		if (nameIDType != null) {
			write(nameIDType, new QName(ASSERTION_NSURI.get(), JBossSAMLConstants.NAMEID.get(), ASSERTION_PREFIX));
		}
		SubjectConfirmationDataType subjectConfirmationData = subjectConfirmationType.getSubjectConfirmationData();
		if (subjectConfirmationData != null) {
			write(subjectConfirmationData);
		}
		StaxUtil.writeEndElement(writer);
	}

	private void write(SubjectConfirmationDataType subjectConfirmationData) throws ProcessingException {
		StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.SUBJECT_CONFIRMATION_DATA.get(),
			ASSERTION_NSURI.get());

		// Let us look at attributes
		String inResponseTo = subjectConfirmationData.getInResponseTo();
		if (StringUtil.isNotNull(inResponseTo)) {
			StaxUtil.writeAttribute(writer, JBossSAMLConstants.IN_RESPONSE_TO.get(), inResponseTo);
		}

		XMLGregorianCalendar notBefore = subjectConfirmationData.getNotBefore();
		if (notBefore != null) {
			DateTime notBeforeTime = new DateTime(
				notBefore.toGregorianCalendar().toInstant().toEpochMilli()
			);
			StaxUtil.writeAttribute(writer, JBossSAMLConstants.NOT_BEFORE.get(), toZuluTime(notBeforeTime));
		}

		XMLGregorianCalendar notOnOrAfter = subjectConfirmationData.getNotOnOrAfter();
		if (notOnOrAfter != null) {
			DateTime notOnOrAfterTime = new DateTime(
				notOnOrAfter.toGregorianCalendar().toInstant().toEpochMilli()
			);
			StaxUtil.writeAttribute(writer, JBossSAMLConstants.NOT_ON_OR_AFTER.get(), toZuluTime(notOnOrAfterTime));
		}

		String recipient = subjectConfirmationData.getRecipient();
		if (StringUtil.isNotNull(recipient)) {
			StaxUtil.writeAttribute(writer, JBossSAMLConstants.RECIPIENT.get(), recipient);
		}

		String address = subjectConfirmationData.getAddress();
		if (StringUtil.isNotNull(address)) {
			StaxUtil.writeAttribute(writer, JBossSAMLConstants.ADDRESS.get(), address);
		}

		if (subjectConfirmationData instanceof KeyInfoConfirmationDataType) {
			KeyInfoConfirmationDataType kicd = (KeyInfoConfirmationDataType) subjectConfirmationData;
			KeyInfoType keyInfo = (KeyInfoType) kicd.getAnyType();
			StaxWriterUtil.writeKeyInfo(writer, keyInfo);
		}

		StaxUtil.writeEndElement(writer);
		StaxUtil.flush(writer);
	}

	private void write(BaseIDAbstractType baseId) throws ProcessingException {
		throw logger.notImplementedYet("Method not implemented.");
	}
}
