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

package org.springframework.security.saml.provider.config;

import java.util.LinkedList;
import java.util.List;

import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;

import static org.springframework.util.StringUtils.hasText;

public class LocalProviderConfiguration <LC extends LocalProviderConfiguration,
	EC extends ExternalProviderConfiguration<EC>> implements Cloneable {

	private String entityId;
	private String alias;
	private boolean signMetadata;
	private String metadata;
	@NestedConfigurationProperty
	private RotatingKeys keys;
	private String prefix;
	private boolean singleLogoutEnabled = true;
	private List<NameId> nameIds = new LinkedList<>();
	private AlgorithmMethod defaultSigningAlgorithm = AlgorithmMethod.RSA_SHA256;
	private DigestMethod defaultDigest = DigestMethod.SHA256;
	private List<EC> providers = new LinkedList<>();
	private String basePath;


	public LocalProviderConfiguration(String prefix) {
		setPrefix(prefix);
	}

	public abstract static class Builder<
			LC extends LocalProviderConfiguration,
			EC extends ExternalProviderConfiguration<EC>,
			T extends Builder<LC, EC, T>> {
        protected LC localProviderConfiguration;

		protected abstract LC createLocalProviderConfigurationInstance();

        public Builder(){
            localProviderConfiguration = createLocalProviderConfigurationInstance();
        }

		public T setEntityId(String entityId) {
			localProviderConfiguration.setEntityId(entityId);
			return self();
		}

		public T setSignMetadata(boolean signMetadata) {
			localProviderConfiguration.setSignMetadata(signMetadata);
			return self();
		}

		public T setMetadata(String metadata) {
			localProviderConfiguration.setMetadata(metadata);
			return self();
		}

		public T setKeys(RotatingKeys keys) {
			localProviderConfiguration.setKeys(keys);
			return self();
		}

		public T setAlias(String alias) {
			localProviderConfiguration.setAlias(alias);
			return self();
		}

		public T setPrefix(String prefix) {
			localProviderConfiguration.setPrefix(prefix);
			return self();
		}

		public T setSingleLogoutEnabled(boolean singleLogoutEnabled) {
			localProviderConfiguration.setSingleLogoutEnabled(singleLogoutEnabled);
			return self();
		}

		public T setNameIds(List<NameId> nameIds) {
			localProviderConfiguration.setNameIds(nameIds);
			return self();
		}

		public T setDefaultSigningAlgorithm(AlgorithmMethod defaultSigningAlgorithm) {
			localProviderConfiguration.setDefaultSigningAlgorithm(defaultSigningAlgorithm);
			return self();
		}

		public T setDefaultDigest(DigestMethod defaultDigest) {
			localProviderConfiguration.setDefaultDigest(defaultDigest);
			return self();
		}

		public T setProviders(List<EC> providers) {
			localProviderConfiguration.setProviders(providers);
			return self();
		}

		public T setBasePath(String basePath) {
			localProviderConfiguration.setBasePath(basePath);
			return self();
		}

		public abstract LC build();

	    //subclasses must override this method to return "this"
        protected  abstract T self();
    }

	protected String cleanPrefix(String prefix) {
		if (hasText(prefix) && prefix.startsWith("/")) {
			prefix = prefix.substring(1);
		}
		if (hasText(prefix) && !prefix.endsWith("/")) {
			prefix = prefix + "/";
		}
		return prefix;
	}

	public String getEntityId() {
		return entityId;
	}

	public void setEntityId(String entityId) {
		this.entityId = entityId;
	}

	public boolean isSignMetadata() {
		return signMetadata;
	}

	public void setSignMetadata(boolean signMetadata) {
		this.signMetadata = signMetadata;
	}

	public String getMetadata() {
		return metadata;
	}

	public void setMetadata(String metadata) {
		this.metadata = metadata;
	}

	public RotatingKeys getKeys() {
		return keys;
	}

	public void setKeys(RotatingKeys keys) {
		this.keys = keys;
	}

	public String getAlias() {
		return alias;
	}

	public void setAlias(String alias) {
		this.alias = alias;
	}

	public String getPrefix() {
		return prefix;
	}

	public void setPrefix(String prefix) {
		this.prefix = cleanPrefix(prefix);
	}

	public boolean isSingleLogoutEnabled() {
		return singleLogoutEnabled;
	}

	public void setSingleLogoutEnabled(boolean singleLogoutEnabled) {
		this.singleLogoutEnabled = singleLogoutEnabled;
	}

	public List<NameId> getNameIds() {
		return nameIds;
	}

	public void setNameIds(List<NameId> nameIds) {
		this.nameIds = nameIds;
	}

	public AlgorithmMethod getDefaultSigningAlgorithm() {
		return defaultSigningAlgorithm;
	}

	public void setDefaultSigningAlgorithm(AlgorithmMethod defaultSigningAlgorithm) {
		this.defaultSigningAlgorithm = defaultSigningAlgorithm;
	}

	public DigestMethod getDefaultDigest() {
		return defaultDigest;
	}

	public void setDefaultDigest(DigestMethod defaultDigest) {
		this.defaultDigest = defaultDigest;
	}

	public String getBasePath() {
		return basePath;
	}

	public void setBasePath(String basePath) {
		this.basePath = basePath;
	}

	@Override
	public LC clone() throws CloneNotSupportedException {
		LC result = (LC) super.clone();
		LinkedList<EC> newProviders = new LinkedList<>();
		for (EC externalConfiguration : getProviders()) {
			newProviders.add(externalConfiguration.clone());
		}
		result.setProviders(newProviders);
		return result;
	}

	public List<EC> getProviders() {
		return providers;
	}

	public void setProviders(List<EC> providers) {
		this.providers = providers;
	}
}
