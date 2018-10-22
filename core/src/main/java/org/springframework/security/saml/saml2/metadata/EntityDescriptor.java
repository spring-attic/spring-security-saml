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
package org.springframework.security.saml.saml2.metadata;

import java.util.LinkedList;
import java.util.List;
import javax.xml.datatype.Duration;

import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.saml2.ImplementationHolder;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;
import org.springframework.security.saml.saml2.signature.Signature;

import org.joda.time.DateTime;

/**
 * Defines EntityDescriptor as defined by
 * https://www.oasis-open.org/committees/download.php/35391/sstc-saml-metadata-errata-2.0-wd-04-diff.pdf
 * Page 13, Line 268
 */
public class EntityDescriptor<T extends EntityDescriptor> extends ImplementationHolder {

	private String id;
	private String entityId;
	private String entityAlias;
	private DateTime validUntil;
	private Duration cacheDuration;
	private List<? extends Provider> providers;
	private Signature signature;
	private SimpleKey signingKey;
	private AlgorithmMethod algorithm;
	private DigestMethod digest;

	EntityDescriptor() {
	}

	EntityDescriptor(EntityDescriptor other) {
		this.id = other.id;
		this.entityId = other.entityId;
		this.entityAlias = other.entityAlias;
		this.validUntil = other.validUntil;
		this.cacheDuration = other.cacheDuration;
		this.providers = other.providers;
		this.signature = other.signature;
		this.signingKey = other.signingKey;
		this.algorithm = other.algorithm;
		this.digest = other.digest;
	}

	public String getId() {
		return id;
	}

	public T setId(String id) {
		this.id = id;
		return _this();
	}

	@SuppressWarnings("unchecked")
	protected T _this() {
		return (T) this;
	}

	public String getEntityId() {
		return entityId;
	}

	public T setEntityId(String entityId) {
		this.entityId = entityId;
		return _this();
	}

	/**
	 * @return the timestamp of the metadata expiration date. null if this value has not been set.
	 */
	public DateTime getValidUntil() {
		return validUntil;
	}

	public T setValidUntil(DateTime validUntil) {
		this.validUntil = validUntil;
		return _this();
	}

	/**
	 * The time interval in format "PnYnMnDTnHnMnS"
	 * <ul>
	 * <li>P indicates the period (required)</li>
	 * <li>nY indicates the number of years</li>
	 * <li>nM indicates the number of months</li>
	 * <li>nD indicates the number of days</li>
	 * <li>T indicates the start of a time section (required if you are going to specify hours, minutes, or
	 * seconds)</li>
	 * <li>nH indicates the number of hours</li>
	 * <li>nM indicates the number of minutes</li>
	 * <li>nS indicates the number of seconds</li>
	 * </ul>
	 *
	 * @return the cache duration for the metadata. null if no duration has been set.
	 */
	public Duration getCacheDuration() {
		return cacheDuration;
	}

	public T setCacheDuration(Duration cacheDuration) {
		this.cacheDuration = cacheDuration;
		return _this();
	}

	public List<SsoProvider> getSsoProviders() {
		List<SsoProvider> result = new LinkedList<>();
		if (getProviders() != null) {
			getProviders()
				.stream()
				.filter(p -> p instanceof SsoProvider)
				.forEach(p -> result.add((SsoProvider) p));
		}
		return result;
	}

	public List<? extends Provider> getProviders() {
		return providers;
	}

	public T setProviders(List<? extends Provider> providers) {
		this.providers = providers;
		return _this();
	}

	public Signature getSignature() {
		return signature;
	}

	public T setSignature(Signature signature) {
		this.signature = signature;
		return _this();
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

	public String getEntityAlias() {
		return entityAlias;
	}

	public T setEntityAlias(String entityAlias) {
		this.entityAlias = entityAlias;
		return _this();
	}

	public T setSigningKey(SimpleKey signingKey, AlgorithmMethod algorithm, DigestMethod digest) {
		this.signingKey = signingKey;
		this.algorithm = algorithm;
		this.digest = digest;
		return _this();
	}

	@Override
	public String getOriginEntityId() {
		return getEntityId();
	}

	@Override
	public String getDestinationEntityId() {
		return null;
	}
}
