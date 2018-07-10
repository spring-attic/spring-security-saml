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

package org.springframework.security.saml;

import org.springframework.security.saml.config.ExternalProviderConfiguration;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.LogoutRequest;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;

/**
 * Helper class that resolves metadata for
 * Service Providers, SP, and Identity Providers, IDP, based on a set of criteria.
 */
public interface SamlObjectResolver {

	/**
	 * Returns the Service Provider metadata for a locally hosted SP
	 *
	 * @param baseUrl the base URL that the SP is hosted at.
	 *                This parameter is used to configure URLs in
	 *                in the metadata data.
	 *
	 * @return ServiceProviderMetadata for a local SP
	 */
	ServiceProviderMetadata getLocalServiceProvider(String baseUrl);

//	ServiceProviderMetadata resolveLocalServiceProvider(HttpServletRequest request);

	/**
	 * Returns the Identity Provider metadata for a locally hosted IDP
	 *
	 * @param baseUrl the base URL that the SP is hosted at.
	 *                This parameter is used to configure URLs in
	 *                in the metadata data.
	 *
	 * @return IdentityProviderMetadata for a local IDP
	 */
	IdentityProviderMetadata getLocalIdentityProvider(String baseUrl);

//	IdentityProviderMetadata resolveLocalIdentityProvider(HttpServletRequest request);

	/**
	 * Under the assumption that the Response originated from an Identity Provider
	 * resolve the configured IDP using the response message
	 * @param response a SAML response message received by a Service Provider
	 * @return IdentityProviderMetadata of the IDP that sent the response
	 */
	IdentityProviderMetadata resolveIdentityProvider(Response response);

	/**
	 * Given a known entityId resolve a configured identity provider
	 * @param entityId entityId of identity provider
	 * @return IdentityProviderMetadata if a provider is configured
	 *         or null if no provider with that entityId is configured
	 */
	IdentityProviderMetadata resolveIdentityProvider(String entityId);

	/**
	 * Based on the external configuration of an Identity Provider resolve the metadata for that provider.
	 * The metadata may be configured locally or may need to be resolved from an external entity
	 * @param idp Identity Provider configuration
	 * @return the metadata for the external Identity Provider
	 */
	IdentityProviderMetadata resolveIdentityProvider(ExternalProviderConfiguration idp);

	/**
	 * Under the assumption that the logout request was sent by an external identity provider
	 * to a local service provider, resolve the configured identity provider
	 * @param logoutRequest the logout request sent by the IDP and received by local SP
	 * @return the configured IDP that sent the logout request or null if not configured
	 */
	IdentityProviderMetadata resolveIdentityProvider(LogoutRequest logoutRequest);

	/**
	 * Under the assumption that the assertion was sent by an external identity provider
	 * to a local service provider, resolve the configured identity provider
	 * @param assertion the assertion request sent by the IDP and received by the local SP
	 * @return the configured IDP that sent the assertion or null if not configured
	 */
	IdentityProviderMetadata resolveIdentityProvider(Assertion assertion);

	/**
	 * Given a known entityId resolve a configured service provider
	 * @param entityId entityId of service provider
	 * @return ServiceProviderMetadata if a provider is configured
	 *         or null if no provider with that entityId is configured
	 */
	ServiceProviderMetadata resolveServiceProvider(String entityId);

	/**
	 * Under the assumption that the authentication request was sent from
	 * a service provider to the local identity provider, resolve the
	 * configured external service provider's metadata
	 * @param request the request that was received by the local identity provider
	 * @return the metadata of the configured external service provider
	 */
	ServiceProviderMetadata resolveServiceProvider(AuthenticationRequest request);

	/**
	 * Based on the external configuration of a Service Provider resolve the metadata for that provider.
	 * The metadata may be configured locally or may need to be resolved from an external entity
	 * @param sp Service Provider configuration
	 * @return the metadata for the external Service Provider
	 */
	ServiceProviderMetadata resolveServiceProvider(ExternalProviderConfiguration sp);

	/**
	 * Under the assumption that the logout request was sent by an external service provider
	 * to a local identity provider, resolve the configured service provider
	 * @param logoutRequest the logout request sent by the SP
	 * @return the configured SP that sent the logout request or null if not configured
	 */
	ServiceProviderMetadata resolveServiceProvider(LogoutRequest logoutRequest);

	/**
	 * For the local identity provider, resolve the external service provider
	 * that the assertion was sent to.
	 * @param localAssertion the assertion that the local IDP issued
	 * @return the configured external SP that received the assertion
	 */
	ServiceProviderMetadata resolveServiceProvider(Assertion localAssertion);
}
