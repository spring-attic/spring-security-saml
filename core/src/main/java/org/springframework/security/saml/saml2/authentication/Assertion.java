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

package org.springframework.security.saml.saml2.authentication;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.saml2.ImplementationHolder;
import org.springframework.security.saml.saml2.attribute.Attribute;
import org.springframework.security.saml.saml2.encrypt.DataEncryptionMethod;
import org.springframework.security.saml.saml2.encrypt.KeyEncryptionMethod;
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
public class Assertion extends ImplementationHolder {

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
	private SimpleKey signingKey;
	private AlgorithmMethod algorithm;
	private DigestMethod digest;
	private SimpleKey encryptionKey;
	private KeyEncryptionMethod keyAlgorithm;
	private DataEncryptionMethod dataAlgorithm;

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

	public SimpleKey getSigningKey() {
		return signingKey;
	}

	public AlgorithmMethod getAlgorithm() {
		return algorithm;
	}

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

	public Assertion setSigningKey(SimpleKey signingKey, AlgorithmMethod algorithm, DigestMethod digest) {
		this.signingKey = signingKey;
		this.algorithm = algorithm;
		this.digest = digest;
		return this;
	}

	public Assertion setEncryptionKey(SimpleKey encryptionKey,
									  KeyEncryptionMethod keyAlgorithm,
									  DataEncryptionMethod dataAlgorithm) {
		this.encryptionKey = encryptionKey;
		this.keyAlgorithm = keyAlgorithm;
		this.dataAlgorithm = dataAlgorithm;
		return this;
	}

	public SimpleKey getEncryptionKey() {
		return encryptionKey;
	}

	public KeyEncryptionMethod getKeyAlgorithm() {
		return keyAlgorithm;
	}

	public DataEncryptionMethod getDataAlgorithm() {
		return dataAlgorithm;
	}
}
