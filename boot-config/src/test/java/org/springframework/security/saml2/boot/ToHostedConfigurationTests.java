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

package org.springframework.security.saml2.boot;

import org.springframework.security.saml2.boot.configuration.LocalSaml2IdentityProviderConfiguration;
import org.springframework.security.saml2.boot.configuration.LocalSaml2ProviderConfiguration;
import org.springframework.security.saml2.boot.configuration.LocalSaml2ServiceProviderConfiguration;
import org.springframework.security.saml2.boot.configuration.RemoteSaml2IdentityProviderConfiguration;
import org.springframework.security.saml2.boot.configuration.RemoteSaml2ProviderConfiguration;
import org.springframework.security.saml2.boot.configuration.RemoteSaml2ServiceProviderConfiguration;
import org.springframework.security.saml2.registration.ExternalSaml2ProviderRegistration;
import org.springframework.security.saml2.registration.HostedSaml2ProviderRegistration;
import org.springframework.security.saml2.registration.ExternalSaml2ServiceProviderRegistration;
import org.springframework.security.saml2.registration.HostedSaml2IdentityProviderRegistration;
import org.springframework.security.saml2.registration.ExternalSaml2IdentityProviderRegistration;
import org.springframework.security.saml2.registration.HostedSaml2ServiceProviderRegistration;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class ToHostedConfigurationTests {

	@Test
	public void testHostedIdpDefaults() {
		LocalSaml2IdentityProviderConfiguration idp = new LocalSaml2IdentityProviderConfiguration();
		assertLocalIdp(idp);
	}

	@Test
	public void testHostedSpDefaults() {
		LocalSaml2ServiceProviderConfiguration sp = new LocalSaml2ServiceProviderConfiguration();
		assertLocalSp(sp);
	}

	private void assertLocalParent(LocalSaml2ProviderConfiguration lc, HostedSaml2ProviderRegistration hc) {
		assertEquals(lc.getPathPrefix(), hc.getPathPrefix(), "pathPrefix");
		assertEquals(lc.getBasePath(), hc.getBasePath(), "basePath");
		assertEquals(lc.getAlias(), hc.getAlias(), "alias");
		assertEquals(lc.getEntityId(), hc.getEntityId(), "entityId");
		assertEquals(lc.isSignMetadata(), hc.isSignMetadata(), "entityId");
		assertEquals(lc.getMetadata(), hc.getMetadata(), "metadata"); //why?
		//keys;
		assertEquals(lc.getDefaultSigningAlgorithm(), hc.getDefaultSigningAlgorithm(), "signingAlgorithm");
		assertEquals(lc.getDefaultDigest(), hc.getDefaultDigest(), "signingDigest");
		assertThat("nameIds", hc.getNameIds(), containsInAnyOrder(lc.getNameIds()));
		assertEquals(lc.isSingleLogoutEnabled(), hc.isSingleLogoutEnabled(), "singleLogoutEnabled");
	}

	private void assertLocalSp(LocalSaml2ServiceProviderConfiguration lc) {
		HostedSaml2ServiceProviderRegistration hc = lc.toHostedServiceProviderRegistration();
		assertLocalParent(lc, hc);
		for (int i=0; i<lc.getProviders().size(); i++) {
			RemoteSaml2IdentityProviderConfiguration rc = lc.getProviders().get(i);
			assertRemoteIdentityProviderConfiguration(rc);
		}

		assertEquals(lc.isSignRequests(), hc.isSignRequests(), "signRequests");
		assertEquals(lc.isWantAssertionsSigned(), hc.isWantAssertionsSigned(), "wantAssertionsSigned");
	}

	private void assertLocalIdp(LocalSaml2IdentityProviderConfiguration lc) {
		HostedSaml2IdentityProviderRegistration hc = lc.toHostedIdentityProviderRegistration();
		assertLocalParent(lc, hc);
		for (int i=0; i<lc.getProviders().size(); i++) {
			RemoteSaml2ServiceProviderConfiguration rc = lc.getProviders().get(i);
			assertRemoteServiceProviderConfiguration(rc);
		}
		assertEquals(lc.isWantRequestsSigned(), hc.isWantRequestsSigned(), "wantRequestsSigned");
		assertEquals(lc.isSignAssertions(), hc.isSignAssertions(), "signAssertions");
		assertEquals(lc.isEncryptAssertions(), hc.isEncryptAssertions(), "encryptAssertions");
		assertEquals(lc.getKeyEncryptionAlgorithm(), hc.getKeyEncryptionAlgorithm(), "keyEncryptionAlgorithm");
		assertEquals(lc.getDataEncryptionAlgorithm(), hc.getDataEncryptionAlgorithm(), "dataEncryptionAlgorithm");
		assertEquals(lc.getNotOnOrAfter(), hc.getNotOnOrAfter(), "notOnOrAfter");
		assertEquals(lc.getNotBefore(), hc.getNotBefore(), "notBefore");
		assertEquals(lc.getDataEncryptionAlgorithm(), hc.getDataEncryptionAlgorithm(), "sessionNotOnOrAfter");
	}

	private void assertRemoteParent(RemoteSaml2ProviderConfiguration rc, ExternalSaml2ProviderRegistration ec) {
		assertEquals(rc.isSkipSslValidation(), ec.isSkipSslValidation(), "skipSslValidation");
		assertEquals(rc.isMetadataTrustCheck(), ec.isMetadataTrustCheck(), "metadataTrustCheck");
		assertEquals(rc.getAlias(), ec.getAlias(), "alias");
		assertEquals(rc.getMetadata(), ec.getMetadata(), "metadata");
		assertEquals(rc.getLinktext(), ec.getLinktext(), "linkText");
	}

	private void assertRemoteIdentityProviderConfiguration(RemoteSaml2IdentityProviderConfiguration rc) {
		ExternalSaml2IdentityProviderRegistration ec = rc.toExternalIdentityProviderRegistration();
		assertRemoteParent(rc, ec);
		assertEquals(rc.getNameId(), ec.getNameId(),"nameId");
		assertEquals(rc.getAssertionConsumerServiceIndex(), ec.getAssertionConsumerServiceIndex(),"assertionConsumerServiceIndex");
	}

	private void assertRemoteServiceProviderConfiguration(RemoteSaml2ServiceProviderConfiguration rc) {
		ExternalSaml2ServiceProviderRegistration ec = rc.toExternalServiceProviderRegistration();
		assertRemoteParent(rc, ec);
	}

}
