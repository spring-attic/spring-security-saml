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
package org.springframework.security.saml.spi;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.LinkedList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.SamlObjectResolver;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.config.ExternalProviderConfiguration;
import org.springframework.security.saml.config.LocalIdentityProviderConfiguration;
import org.springframework.security.saml.config.LocalProviderConfiguration;
import org.springframework.security.saml.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.config.SamlServerConfiguration;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.Issuer;
import org.springframework.security.saml.saml2.authentication.LogoutRequest;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.util.Network;

import static org.springframework.util.StringUtils.hasText;

public class DefaultSamlObjectResolver implements SamlObjectResolver {

	private SamlServerConfiguration configuration;
	private Defaults defaults;
	private SamlTransformer transformer;
	private Network network;
	private DefaultMetadataCache cache;

	@Autowired
	public void setTransformer(SamlTransformer transformer) {
		this.transformer = transformer;
	}

	@Autowired
	public DefaultSamlObjectResolver setSamlServerConfiguration(SamlServerConfiguration configuration) {
		this.configuration = configuration;
		return this;
	}

	@Autowired
	public DefaultSamlObjectResolver setDefaults(Defaults defaults) {
		this.defaults = defaults;
		return this;
	}

	@Autowired
	public DefaultSamlObjectResolver setNetwork(Network network) {
		this.network = network;
		return this;
	}

	@Autowired
	public DefaultSamlObjectResolver setMetadataCache(DefaultMetadataCache cache) {
		this.cache = cache;
		return this;
	}

	@Override
	public ServiceProviderMetadata getLocalServiceProvider(String baseUrl) {
		LocalServiceProviderConfiguration sp = configuration.getServiceProvider();
		List<SimpleKey> keys = getSimpleKeys(sp);
		SimpleKey signing = sp.isSignMetadata() ? sp.getKeys().getActive().get(0) : null;
		ServiceProviderMetadata metadata = defaults.serviceProviderMetadata(baseUrl, keys, signing);
		if (hasText(sp.getEntityId())) {
			metadata.setEntityId(sp.getEntityId());
		}
		if (hasText(sp.getName())) {
			metadata.setEntityAlias(sp.getName());
		}
		metadata.getServiceProvider().setWantAssertionsSigned(sp.isWantAssertionsSigned());
		metadata.getServiceProvider().setAuthnRequestsSigned(sp.isSignRequests());
		return metadata;
	}

	@Override
	public IdentityProviderMetadata getLocalIdentityProvider(String baseUrl) {
		LocalIdentityProviderConfiguration idp = configuration.getIdentityProvider();
		List<SimpleKey> keys = getSimpleKeys(idp);
		SimpleKey signing = idp.isSignMetadata() ? idp.getKeys().getActive().get(0) : null;
		IdentityProviderMetadata metadata = defaults.identityProviderMetadata(baseUrl, keys, signing);
		if (hasText(idp.getEntityId())) {
			metadata.setEntityId(idp.getEntityId());
		}
		if (hasText(idp.getName())) {
			metadata.setEntityAlias(idp.getName());
		}

		metadata.getIdentityProvider().setWantAuthnRequestsSigned(idp.isWantRequestsSigned());
		return metadata;
	}

	@Override
	public IdentityProviderMetadata resolveIdentityProvider(Assertion assertion) {
		Issuer issuer = assertion.getIssuer();
		return resolveIdentityProvider(issuer.getValue());
	}

	@Override
	public IdentityProviderMetadata resolveIdentityProvider(Response response) {
		Issuer issuer = response.getIssuer();
		return resolveIdentityProvider(issuer.getValue());
	}

	@Override
	public IdentityProviderMetadata resolveIdentityProvider(String entityId) {
		for (ExternalProviderConfiguration c : configuration.getServiceProvider().getProviders()) {
			IdentityProviderMetadata idp = resolveIdentityProvider(c);
			if (idp != null && entityId.equals(idp.getEntityId())) {
				return idp;
			}
		}
		return null;
	}

	@Override
	public IdentityProviderMetadata resolveIdentityProvider(LogoutRequest logoutRequest) {
		return resolveIdentityProvider(logoutRequest.getIssuer().getValue());
	}

	@Override
	public IdentityProviderMetadata resolveIdentityProvider(ExternalProviderConfiguration idp) {
		return (IdentityProviderMetadata) resolve(idp.getMetadata(), idp.isSkipSslValidation());
	}

	@Override
	public ServiceProviderMetadata resolveServiceProvider(String entityId) {
		LocalIdentityProviderConfiguration idp = configuration.getIdentityProvider();
		for (ExternalProviderConfiguration c : idp.getProviders()) {
			String metadata = c.getMetadata();
			Metadata m = resolve(metadata, c.isSkipSslValidation());
			if (m instanceof ServiceProviderMetadata && entityId.equals(m.getEntityId())) {
				return (ServiceProviderMetadata) m;
			}
		}
		return null;
	}

	@Override
	public ServiceProviderMetadata resolveServiceProvider(AuthenticationRequest request) {
		Issuer issuer = request.getIssuer();
		ServiceProviderMetadata result = resolveServiceProvider(issuer.getValue());
		return result;
	}

	@Override
	public ServiceProviderMetadata resolveServiceProvider(ExternalProviderConfiguration sp) {
		return (ServiceProviderMetadata) resolve(sp.getMetadata(), sp.isSkipSslValidation());
	}

	@Override
	public ServiceProviderMetadata resolveServiceProvider(LogoutRequest logoutRequest) {
		return resolveServiceProvider(logoutRequest.getIssuer().getValue());
	}

	protected Metadata resolve(String metadata, boolean skipSslValidation) {
		Metadata result = null;
		if (isUri(metadata)) {
			try {
				byte[] data = cache.getMetadata(metadata, skipSslValidation);
				result = (Metadata) transformer.fromXml(data, null, null);
			} catch (Exception x) {
				x.printStackTrace();
			}
		}
		else {
			result = (Metadata) transformer.fromXml(metadata, null, null);
		}
		return result;
	}

	protected boolean isUri(String uri) {
		boolean isUri = false;
		try {
			new URI(uri);
			isUri = true;
		} catch (URISyntaxException e) {
		}
		return isUri;
	}

	protected List<SimpleKey> getSimpleKeys(LocalProviderConfiguration sp) {
		List<SimpleKey> keys = new LinkedList<>();
		keys.addAll(sp.getKeys().getActive());
		keys.addAll(sp.getKeys().getStandBy());
		return keys;
	}
}
