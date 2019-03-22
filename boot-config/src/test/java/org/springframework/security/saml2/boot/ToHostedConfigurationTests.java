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

import org.springframework.security.saml2.boot.configuration.LocalIdentityProviderConfiguration;
import org.springframework.security.saml2.boot.configuration.LocalProviderConfiguration;
import org.springframework.security.saml2.boot.configuration.LocalServiceProviderConfiguration;
import org.springframework.security.saml2.boot.configuration.RemoteIdentityProviderConfiguration;
import org.springframework.security.saml2.boot.configuration.RemoteProviderConfiguration;
import org.springframework.security.saml2.boot.configuration.RemoteServiceProviderConfiguration;
import org.springframework.security.saml2.configuration.ExternalSaml2ProviderConfiguration;
import org.springframework.security.saml2.configuration.HostedSaml2ProviderConfiguration;
import org.springframework.security.saml2.configuration.ExternalSaml2ServiceProviderConfiguration;
import org.springframework.security.saml2.configuration.HostedSaml2IdentityProviderConfiguration;
import org.springframework.security.saml2.configuration.ExternalSaml2IdentityProviderConfiguration;
import org.springframework.security.saml2.configuration.HostedSaml2ServiceProviderConfiguration;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class ToHostedConfigurationTests {

	@Test
	public void testHostedIdpDefaults() {
		LocalIdentityProviderConfiguration idp = new LocalIdentityProviderConfiguration();
		assertLocalIdp(idp);
	}

	@Test
	public void testHostedSpDefaults() {
		LocalServiceProviderConfiguration sp = new LocalServiceProviderConfiguration();
		assertLocalSp(sp);
	}

	private void assertLocalParent(LocalProviderConfiguration lc, HostedSaml2ProviderConfiguration hc) {
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

	private void assertLocalSp(LocalServiceProviderConfiguration lc) {
		HostedSaml2ServiceProviderConfiguration hc = lc.toHostedConfiguration();
		assertLocalParent(lc, hc);
		for (int i=0; i<lc.getProviders().size(); i++) {
			RemoteIdentityProviderConfiguration rc = lc.getProviders().get(i);
			assertRemoteIdentityProviderConfiguration(rc);
		}

		assertEquals(lc.isSignRequests(), hc.isSignRequests(), "signRequests");
		assertEquals(lc.isWantAssertionsSigned(), hc.isWantAssertionsSigned(), "wantAssertionsSigned");
	}

	private void assertLocalIdp(LocalIdentityProviderConfiguration lc) {
		HostedSaml2IdentityProviderConfiguration hc = lc.toHostedConfiguration();
		assertLocalParent(lc, hc);
		for (int i=0; i<lc.getProviders().size(); i++) {
			RemoteServiceProviderConfiguration rc = lc.getProviders().get(i);
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

	private void assertRemoteParent(RemoteProviderConfiguration rc, ExternalSaml2ProviderConfiguration ec) {
		assertEquals(rc.isSkipSslValidation(), ec.isSkipSslValidation(), "skipSslValidation");
		assertEquals(rc.isMetadataTrustCheck(), ec.isMetadataTrustCheck(), "metadataTrustCheck");
		assertEquals(rc.getAlias(), ec.getAlias(), "alias");
		assertEquals(rc.getMetadata(), ec.getMetadata(), "metadata");
		assertEquals(rc.getLinktext(), ec.getLinktext(), "linkText");
	}

	private void assertRemoteIdentityProviderConfiguration(RemoteIdentityProviderConfiguration rc) {
		ExternalSaml2IdentityProviderConfiguration ec = rc.toExternalIdentityProviderConfiguration();
		assertRemoteParent(rc, ec);
		assertEquals(rc.getNameId(), ec.getNameId(),"nameId");
		assertEquals(rc.getAssertionConsumerServiceIndex(), ec.getAssertionConsumerServiceIndex(),"assertionConsumerServiceIndex");
	}

	private void assertRemoteServiceProviderConfiguration(RemoteServiceProviderConfiguration rc) {
		ExternalSaml2ServiceProviderConfiguration ec = rc.toExternalServiceProviderConfiguration();
		assertRemoteParent(rc, ec);
	}

}
