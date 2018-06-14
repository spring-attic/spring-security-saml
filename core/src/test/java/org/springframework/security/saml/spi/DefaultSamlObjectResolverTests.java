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

import java.io.IOException;
import java.time.Clock;

import org.springframework.security.saml.config.ExternalIdentityProviderConfiguration;
import org.springframework.security.saml.config.ExternalServiceProviderConfiguration;
import org.springframework.security.saml.config.LocalIdentityProviderConfiguration;
import org.springframework.security.saml.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.config.SamlServerConfiguration;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.MetadataBase;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.spi.opensaml.OpenSamlImplementation;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static java.util.Arrays.asList;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

class DefaultSamlObjectResolverTests extends MetadataBase {

	private DefaultSamlObjectResolver resolver;
	private DefaultMetadataCache cache;
	private DefaultSamlTransformer transformer;


	@BeforeEach
	void populateCache() throws IOException {
		transformer = new DefaultSamlTransformer(new OpenSamlImplementation(Clock.systemUTC()).init());

		cache = Mockito.mock(DefaultMetadataCache.class);

		ExternalServiceProviderConfiguration extSp = new ExternalServiceProviderConfiguration()
			.setMetadata("http://test.test.test");

		LocalIdentityProviderConfiguration localIdp = new LocalIdentityProviderConfiguration()
			.setProviders(asList(extSp));

		ExternalIdentityProviderConfiguration extIdp = new ExternalIdentityProviderConfiguration()
			.setMetadata("http://test.test.test");

		LocalServiceProviderConfiguration localSp = new LocalServiceProviderConfiguration()
			.setProviders(asList(extIdp));

		resolver = new DefaultSamlObjectResolver()
			.setMetadataCache(cache)
			.setSamlServerConfiguration(
				new SamlServerConfiguration()
					.setIdentityProvider(localIdp)
					.setServiceProvider(localSp)

			)
			.setTransformer(transformer);
	}

	@Test
	public void resolveSpByEntityIdFromEntitesDescriptors() throws Exception {
		byte[] xml = getFileBytes("/test-data/metadata/entities-descriptor-example.xml");
		when(cache.getMetadata(anyString(), anyBoolean())).thenReturn(xml);
		ServiceProviderMetadata sp = resolver.resolveServiceProvider("login.run.pivotal.io");
		assertNotNull(sp);
		IdentityProviderMetadata idp = resolver.resolveIdentityProvider("login.run.pivotal.io");
		assertNotNull(idp);
	}
}