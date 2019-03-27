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

package org.springframework.security.saml2.model.authentication;

import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.springframework.security.saml2.model.Saml2EncryptableObject;
import org.springframework.security.saml2.model.Saml2ImplementationHolder;
import org.springframework.security.saml2.model.Saml2SignableObject;
import org.springframework.security.saml2.model.attribute.Saml2Attribute;
import org.springframework.security.saml2.model.encrypt.Saml2DataEncryptionMethod;
import org.springframework.security.saml2.model.encrypt.Saml2KeyEncryptionMethod;
import org.springframework.security.saml2.model.key.Saml2KeyData;
import org.springframework.security.saml2.model.signature.Saml2AlgorithmMethod;
import org.springframework.security.saml2.model.signature.Saml2DigestMethod;
import org.springframework.security.saml2.model.signature.Saml2Signature;

import org.joda.time.DateTime;

import static java.util.stream.Collectors.toList;

/**
 * Implementation saml:AssertionType as defined by
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 * Page 17, Line 649
 */
public class Saml2Assertion extends Saml2ImplementationHolder<Saml2Assertion>
	implements Saml2SignableObject<Saml2Assertion>, Saml2EncryptableObject<Saml2Assertion> {

	private String version;
	private String id;
	private DateTime issueInstant;
	private Saml2Issuer issuer;
	private Saml2Signature signature;
	private Saml2Subject subject;
	private Saml2Conditions conditions;
	private Saml2Advice advice;
	private List<Saml2AuthenticationStatement> authenticationStatements = new LinkedList<>();
	private List<Saml2Attribute> attributes = new LinkedList<>();
	private Saml2KeyData signingKey;
	private Saml2AlgorithmMethod algorithm;
	private Saml2DigestMethod digest;
	private Saml2KeyData encryptionKey;
	private Saml2KeyEncryptionMethod keyAlgorithm;
	private Saml2DataEncryptionMethod dataAlgorithm;
	private final boolean encrypted;

	public Saml2Assertion() {
		this(false);
	}

	public Saml2Assertion(boolean encrypted) {
		this.encrypted = encrypted;
	}

	public String getVersion() {
		return version;
	}

	public Saml2Assertion setVersion(String version) {
		this.version = version;
		return this;
	}

	public String getId() {
		return id;
	}

	public Saml2Assertion setId(String id) {
		this.id = id;
		return this;
	}

	public DateTime getIssueInstant() {
		return issueInstant;
	}

	public Saml2Assertion setIssueInstant(DateTime issueInstant) {
		this.issueInstant = issueInstant;
		return this;
	}

	public Saml2Issuer getIssuer() {
		return issuer;
	}

	public Saml2Assertion setIssuer(Saml2Issuer issuer) {
		this.issuer = issuer;
		return this;
	}

	public Saml2Signature getSignature() {
		return signature;
	}

	public Saml2Assertion setSignature(Saml2Signature signature) {
		this.signature = signature;
		return this;
	}

	public Saml2Subject getSubject() {
		return subject;
	}

	public Saml2Assertion setSubject(Saml2Subject subject) {
		this.subject = subject;
		return this;
	}

	public Saml2Conditions getConditions() {
		return conditions;
	}

	public Saml2Assertion setConditions(Saml2Conditions conditions) {
		this.conditions = conditions;
		return this;
	}

	public Saml2Advice getAdvice() {
		return advice;
	}

	public Saml2Assertion setAdvice(Saml2Advice advice) {
		this.advice = advice;
		return this;
	}

	public List<Saml2AuthenticationStatement> getAuthenticationStatements() {
		return Collections.unmodifiableList(authenticationStatements);
	}

	public Saml2Assertion setAuthenticationStatements(List<Saml2AuthenticationStatement> authenticationStatements) {
		this.authenticationStatements.clear();
		this.authenticationStatements.addAll(authenticationStatements);
		return this;
	}

	public List<Saml2Attribute> getAttributes() {
		return Collections.unmodifiableList(attributes);
	}

	public Saml2Assertion setAttributes(List<Saml2Attribute> attributes) {
		this.attributes.clear();
		this.attributes.addAll(attributes);
		return this;
	}

	@Override
	public Saml2KeyData getSigningKey() {
		return signingKey;
	}

	@Override
	public Saml2AlgorithmMethod getAlgorithm() {
		return algorithm;
	}

	@Override
	public Saml2DigestMethod getDigest() {
		return digest;
	}

	public Saml2Assertion setIssuer(String issuer) {
		this.issuer = new Saml2Issuer().setValue(issuer);
		return this;
	}

	public List<Saml2Attribute> getAttributes(String name) {
		return attributes
			.stream()
			.filter(a -> name.equals(a.getName()))
			.collect(toList());
	}

	public Saml2Attribute getFirstAttribute(String name) {
		Optional<Saml2Attribute> first = attributes
			.stream()
			.filter(a -> name.equals(a.getName()))
			.findFirst();
		return first.isPresent() ? first.get() : null;
	}

	public Saml2Assertion addAuthenticationStatement(Saml2AuthenticationStatement statement) {
		this.authenticationStatements.add(statement);
		return this;
	}

	public Saml2Assertion addAttribute(Saml2Attribute attribute) {
		this.attributes.add(attribute);
		return this;
	}

	@Override
	public Saml2Assertion setSigningKey(Saml2KeyData signingKey, Saml2AlgorithmMethod algorithm, Saml2DigestMethod digest) {
		this.signingKey = signingKey;
		this.algorithm = algorithm;
		this.digest = digest;
		return this;
	}

	@Override
	public Saml2Assertion setEncryptionKey(Saml2KeyData encryptionKey,
										   Saml2KeyEncryptionMethod keyAlgorithm,
										   Saml2DataEncryptionMethod dataAlgorithm) {
		this.encryptionKey = encryptionKey;
		this.keyAlgorithm = keyAlgorithm;
		this.dataAlgorithm = dataAlgorithm;
		return this;
	}

	@Override
	public Saml2KeyData getEncryptionKey() {
		return encryptionKey;
	}

	@Override
	public Saml2KeyEncryptionMethod getKeyAlgorithm() {
		return keyAlgorithm;
	}

	@Override
	public Saml2DataEncryptionMethod getDataAlgorithm() {
		return dataAlgorithm;
	}

	/**
	 * Returns true if this object was parsed as an encrypted object and was
	 * successfully decrypted.
	 * We consider a successful decryption equivalent with a signature validation
	 * @return true if the object parsed was encrypted at the time of decoding
	 */
	public boolean isEncrypted() {
		return encrypted;
	}

	@Override
	public String getOriginEntityId() {
		if (issuer != null) {
			return issuer.getValue();
		}
		return null;
	}

	@Override
	public String getDestinationEntityId() {
		if (conditions != null && conditions.getCriteria() != null) {
			Set<String> audiences = new HashSet<>();
			conditions.getCriteria().stream()
					.filter(ac -> ac instanceof Saml2AudienceRestriction)
					.forEach(ar -> audiences.addAll(((Saml2AudienceRestriction)ar).getAudiences()));
			if (audiences.size()==1) {
				return audiences.iterator().next();
			}
		}
		return null;
	}
}
