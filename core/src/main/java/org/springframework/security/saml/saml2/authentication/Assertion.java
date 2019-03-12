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

package org.springframework.security.saml.saml2.authentication;

import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.springframework.security.saml.saml2.EncryptableSaml2Object;
import org.springframework.security.saml.saml2.ImplementationHolder;
import org.springframework.security.saml.saml2.SignableSaml2Object;
import org.springframework.security.saml.saml2.attribute.Attribute;
import org.springframework.security.saml.saml2.encrypt.DataEncryptionMethod;
import org.springframework.security.saml.saml2.encrypt.KeyEncryptionMethod;
import org.springframework.security.saml.saml2.key.KeyData;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;
import org.springframework.security.saml.saml2.signature.Signature;

import org.joda.time.DateTime;

import static java.util.stream.Collectors.toList;

/**
 * Implementation saml:AssertionType as defined by
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 * Page 17, Line 649
 */
public class Assertion extends ImplementationHolder<Assertion>
	implements SignableSaml2Object<Assertion>, EncryptableSaml2Object<Assertion> {

	private String version;
	private String id;
	private DateTime issueInstant;
	private Issuer issuer;
	private Signature signature;
	private Subject subject;
	private Conditions conditions;
	private Advice advice;
	private List<AuthenticationStatement> authenticationStatements = new LinkedList<>();
	private List<Attribute> attributes = new LinkedList<>();
	private KeyData signingKey;
	private AlgorithmMethod algorithm;
	private DigestMethod digest;
	private KeyData encryptionKey;
	private KeyEncryptionMethod keyAlgorithm;
	private DataEncryptionMethod dataAlgorithm;
	private final boolean encrypted;

	public Assertion() {
		this(false);
	}

	public Assertion(boolean encrypted) {
		this.encrypted = encrypted;
	}

	public String getVersion() {
		return version;
	}

	public Assertion setVersion(String version) {
		this.version = version;
		return this;
	}

	public String getId() {
		return id;
	}

	public Assertion setId(String id) {
		this.id = id;
		return this;
	}

	public DateTime getIssueInstant() {
		return issueInstant;
	}

	public Assertion setIssueInstant(DateTime issueInstant) {
		this.issueInstant = issueInstant;
		return this;
	}

	public Issuer getIssuer() {
		return issuer;
	}

	public Assertion setIssuer(Issuer issuer) {
		this.issuer = issuer;
		return this;
	}

	public Signature getSignature() {
		return signature;
	}

	public Assertion setSignature(Signature signature) {
		this.signature = signature;
		return this;
	}

	public Subject getSubject() {
		return subject;
	}

	public Assertion setSubject(Subject subject) {
		this.subject = subject;
		return this;
	}

	public Conditions getConditions() {
		return conditions;
	}

	public Assertion setConditions(Conditions conditions) {
		this.conditions = conditions;
		return this;
	}

	public Advice getAdvice() {
		return advice;
	}

	public Assertion setAdvice(Advice advice) {
		this.advice = advice;
		return this;
	}

	public List<AuthenticationStatement> getAuthenticationStatements() {
		return Collections.unmodifiableList(authenticationStatements);
	}

	public Assertion setAuthenticationStatements(List<AuthenticationStatement> authenticationStatements) {
		this.authenticationStatements.clear();
		this.authenticationStatements.addAll(authenticationStatements);
		return this;
	}

	public List<Attribute> getAttributes() {
		return Collections.unmodifiableList(attributes);
	}

	public Assertion setAttributes(List<Attribute> attributes) {
		this.attributes.clear();
		this.attributes.addAll(attributes);
		return this;
	}

	@Override
	public KeyData getSigningKey() {
		return signingKey;
	}

	@Override
	public AlgorithmMethod getAlgorithm() {
		return algorithm;
	}

	@Override
	public DigestMethod getDigest() {
		return digest;
	}

	public Assertion setIssuer(String issuer) {
		this.issuer = new Issuer().setValue(issuer);
		return this;
	}

	public List<Attribute> getAttributes(String name) {
		return attributes
			.stream()
			.filter(a -> name.equals(a.getName()))
			.collect(toList());
	}

	public Attribute getFirstAttribute(String name) {
		Optional<Attribute> first = attributes
			.stream()
			.filter(a -> name.equals(a.getName()))
			.findFirst();
		return first.isPresent() ? first.get() : null;
	}

	public Assertion addAuthenticationStatement(AuthenticationStatement statement) {
		this.authenticationStatements.add(statement);
		return this;
	}

	public Assertion addAttribute(Attribute attribute) {
		this.attributes.add(attribute);
		return this;
	}

	@Override
	public Assertion setSigningKey(KeyData signingKey, AlgorithmMethod algorithm, DigestMethod digest) {
		this.signingKey = signingKey;
		this.algorithm = algorithm;
		this.digest = digest;
		return this;
	}

	@Override
	public Assertion setEncryptionKey(KeyData encryptionKey,
									  KeyEncryptionMethod keyAlgorithm,
									  DataEncryptionMethod dataAlgorithm) {
		this.encryptionKey = encryptionKey;
		this.keyAlgorithm = keyAlgorithm;
		this.dataAlgorithm = dataAlgorithm;
		return this;
	}

	@Override
	public KeyData getEncryptionKey() {
		return encryptionKey;
	}

	@Override
	public KeyEncryptionMethod getKeyAlgorithm() {
		return keyAlgorithm;
	}

	@Override
	public DataEncryptionMethod getDataAlgorithm() {
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
					.filter(ac -> ac instanceof AudienceRestriction)
					.forEach(ar -> audiences.addAll(((AudienceRestriction)ar).getAudiences()));
			if (audiences.size()==1) {
				return audiences.iterator().next();
			}
		}
		return null;
	}
}
