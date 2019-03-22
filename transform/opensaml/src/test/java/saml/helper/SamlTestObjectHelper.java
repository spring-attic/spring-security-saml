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

package saml.helper;


import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.time.Clock;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.security.saml2.configuration.HostedSaml2IdentityProviderConfiguration;
import org.springframework.security.saml2.configuration.HostedSaml2ProviderConfiguration;
import org.springframework.security.saml2.configuration.HostedSaml2ServiceProviderConfiguration;
import org.springframework.security.saml2.model.authentication.Saml2Assertion;
import org.springframework.security.saml2.model.authentication.Saml2AudienceRestriction;
import org.springframework.security.saml2.model.authentication.Saml2AuthenticationSaml2Request;
import org.springframework.security.saml2.model.authentication.Saml2AuthenticationStatement;
import org.springframework.security.saml2.model.authentication.Saml2Conditions;
import org.springframework.security.saml2.model.authentication.Saml2Issuer;
import org.springframework.security.saml2.model.authentication.Saml2LogoutSaml2Request;
import org.springframework.security.saml2.model.authentication.Saml2LogoutResponseSaml2;
import org.springframework.security.saml2.model.authentication.Saml2NameIdPolicy;
import org.springframework.security.saml2.model.authentication.Saml2NameIdPrincipalSaml2;
import org.springframework.security.saml2.model.authentication.Saml2ResponseSaml2;
import org.springframework.security.saml2.model.authentication.Saml2Status;
import org.springframework.security.saml2.model.authentication.Saml2StatusCode;
import org.springframework.security.saml2.model.authentication.Saml2Subject;
import org.springframework.security.saml2.model.authentication.Saml2SubjectConfirmation;
import org.springframework.security.saml2.model.authentication.Saml2SubjectConfirmationData;
import org.springframework.security.saml2.model.authentication.Saml2SubjectConfirmationMethod;
import org.springframework.security.saml2.model.key.Saml2KeyData;
import org.springframework.security.saml2.model.metadata.Saml2Binding;
import org.springframework.security.saml2.model.metadata.Saml2BindingType;
import org.springframework.security.saml2.model.metadata.Saml2Endpoint;
import org.springframework.security.saml2.model.metadata.Saml2IdentityProvider;
import org.springframework.security.saml2.model.metadata.Saml2IdentityProviderMetadata;
import org.springframework.security.saml2.model.metadata.Saml2Metadata;
import org.springframework.security.saml2.model.metadata.Saml2NameId;
import org.springframework.security.saml2.model.metadata.ServiceProvider;
import org.springframework.security.saml2.model.metadata.ServiceProviderMetadata;
import org.springframework.security.saml2.model.signature.AlgorithmMethod;
import org.springframework.security.saml2.model.signature.DigestMethod;
import org.springframework.security.saml2.util.Saml2StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import org.joda.time.DateTime;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static org.springframework.security.saml2.model.metadata.Saml2Binding.REDIRECT;
import static org.springframework.security.saml2.model.signature.AlgorithmMethod.RSA_SHA1;
import static org.springframework.security.saml2.model.signature.DigestMethod.SHA1;
import static org.springframework.util.StringUtils.hasText;

public class SamlTestObjectHelper {
	public AlgorithmMethod DEFAULT_SIGN_ALGORITHM = RSA_SHA1;
	public DigestMethod DEFAULT_SIGN_DIGEST = SHA1;
	public long NOT_BEFORE = 60000;
	public long NOT_AFTER = 120000;
	public long SESSION_NOT_AFTER = 30 * 60 * 1000;

	private Clock time;

	public SamlTestObjectHelper(Clock time) {
		this.time = time;
	}

	public Clock getTime() {
		return time;
	}

	public SamlTestObjectHelper setTime(Clock time) {
		this.time = time;
		return this;
	}

	public ServiceProviderMetadata serviceProviderMetadata(String baseUrl,
														   HostedSaml2ServiceProviderConfiguration configuration) {
		List<Saml2KeyData> keys = configuration.getKeys();
		Saml2KeyData signingKey = configuration.isSignMetadata() && keys.size()>0 ? keys.get(0) : null;

		String aliasPath = getAliasPath(configuration);
		String pathPrefix = hasText(configuration.getPathPrefix()) ? configuration.getPathPrefix() : "saml/sp/";

		ServiceProviderMetadata metadata =
			serviceProviderMetadata(
				baseUrl,
				signingKey,
				keys,
				pathPrefix,
				aliasPath,
				configuration.getDefaultSigningAlgorithm(),
				configuration.getDefaultDigest()
			);

		if (!configuration.getNameIds().isEmpty()) {
			metadata.getServiceProvider().setNameIds(configuration.getNameIds());
		}

		return metadata;
	}

	protected String getAliasPath(HostedSaml2ProviderConfiguration configuration) {
		return UriUtils.encode(
			Saml2StringUtils.getAliasPath(configuration.getAlias(), configuration.getEntityId()),
			"ISO-8859-1"
		);
	}

	public ServiceProviderMetadata serviceProviderMetadata(String baseUrl,
														   Saml2KeyData signingKey,
														   List<Saml2KeyData> keys,
														   String pathPrefix,
														   String aliasPath,
														   AlgorithmMethod algorithmMethod,
														   DigestMethod digestMethod) {

		return new ServiceProviderMetadata()
			.setEntityId(baseUrl)
			.setId("SPM"+UUID.randomUUID().toString())
			.setSigningKey(
				signingKey,
				algorithmMethod == null ? DEFAULT_SIGN_ALGORITHM : algorithmMethod,
				digestMethod == null ? DEFAULT_SIGN_DIGEST : digestMethod
			)
			.setProviders(
				asList(
					new ServiceProvider()
						.setKeys(keys)
						.setWantAssertionsSigned(true)
						.setAuthnRequestsSigned(signingKey != null)
						.setAssertionConsumerService(
							asList(
								getEndpoint(baseUrl, pathPrefix + "SSO/alias/" + aliasPath, Saml2Binding.POST, 0, true),
								getEndpoint(baseUrl, pathPrefix + "SSO/alias/" + aliasPath, REDIRECT, 1, false)
							)
						)
						.setNameIds(asList(Saml2NameId.PERSISTENT, Saml2NameId.EMAIL))
						.setKeys(keys)
						.setSingleLogoutService(
							asList(
								getEndpoint(baseUrl, pathPrefix + "logout/alias/" + aliasPath, REDIRECT, 0, true)
							)
						)
				)
			);
	}

	public Saml2Endpoint getEndpoint(String baseUrl, String path, Saml2Binding binding, int index, boolean isDefault) {
		UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(baseUrl);
		builder.pathSegment(path);
		return getEndpoint(builder.build().toUriString(), binding, index, isDefault);
	}

	public Saml2Endpoint getEndpoint(String url, Saml2Binding binding, int index, boolean isDefault) {
		return
			new Saml2Endpoint()
				.setIndex(index)
				.setBinding(binding)
				.setLocation(url)
				.setDefault(isDefault)
				.setIndex(index);
	}

	public Saml2IdentityProviderMetadata identityProviderMetadata(String baseUrl,
																  HostedSaml2IdentityProviderConfiguration configuration) {
		List<Saml2KeyData> keys = configuration.getKeys();
		Saml2KeyData signingKey = configuration.isSignMetadata() && keys.size()>0 ? keys.get(0) : null;

		String pathPrefix = hasText(configuration.getPathPrefix()) ? configuration.getPathPrefix() : "saml/idp/";
		String aliasPath = getAliasPath(configuration);
		Saml2IdentityProviderMetadata metadata = identityProviderMetadata(
			baseUrl,
			signingKey,
			keys,
			pathPrefix,
			aliasPath,
			configuration.getDefaultSigningAlgorithm(),
			configuration.getDefaultDigest()
		);
		if (!configuration.getNameIds().isEmpty()) {
			metadata.getIdentityProvider().setNameIds(configuration.getNameIds());
		}
		return metadata;
	}

	public Saml2IdentityProviderMetadata identityProviderMetadata(String baseUrl,
																  Saml2KeyData signingKey,
																  List<Saml2KeyData> keys,
																  String pathPrefix,
																  String aliasPath,
																  AlgorithmMethod algorithmMethod,
																  DigestMethod digestMethod) {

		return new Saml2IdentityProviderMetadata()
			.setEntityId(baseUrl)
			.setId("IDPM"+UUID.randomUUID().toString())
			.setSigningKey(
				signingKey,
				algorithmMethod == null ? DEFAULT_SIGN_ALGORITHM : algorithmMethod,
				digestMethod == null ? DEFAULT_SIGN_DIGEST : digestMethod
			)
			.setProviders(
				asList(
					new Saml2IdentityProvider()
						.setWantAuthnRequestsSigned(true)
						.setSingleSignOnService(
							asList(
								getEndpoint(baseUrl, pathPrefix + "SSO/alias/" + aliasPath, Saml2Binding.POST, 0, true),
								getEndpoint(baseUrl, pathPrefix + "SSO/alias/" + aliasPath, REDIRECT, 1, false)
							)
						)
						.setNameIds(asList(Saml2NameId.PERSISTENT, Saml2NameId.EMAIL))
						.setKeys(keys)
						.setSingleLogoutService(
							asList(
								getEndpoint(baseUrl, pathPrefix + "logout/alias/" + aliasPath, REDIRECT, 0, true)
							)
						)
				)
			);

	}

	public Saml2AuthenticationSaml2Request authenticationRequest(ServiceProviderMetadata sp, Saml2IdentityProviderMetadata idp) {

		Saml2AuthenticationSaml2Request request = new Saml2AuthenticationSaml2Request()
			.setId("ARQ"+UUID.randomUUID().toString())
			.setIssueInstant(new DateTime(time.millis()))
			.setForceAuth(Boolean.FALSE)
			.setPassive(Boolean.FALSE)
			.setBinding(Saml2Binding.POST)
			.setAssertionConsumerService(getACSFromSp(sp))
			.setIssuer(new Saml2Issuer().setValue(sp.getEntityId()))
			.setDestination(idp.getIdentityProvider().getSingleSignOnService().get(0));
		if (sp.getServiceProvider().isAuthnRequestsSigned()) {
			request.setSigningKey(sp.getSigningKey(), sp.getAlgorithm(), sp.getDigest());
		}
		Saml2NameIdPolicy policy;
		if (idp.getDefaultNameId() != null) {
			policy = new Saml2NameIdPolicy(
				idp.getDefaultNameId(),
				sp.getEntityAlias(),
				true
			);
		}
		else {
			policy = new Saml2NameIdPolicy(
				idp.getIdentityProvider().getNameIds().get(0),
				sp.getEntityAlias(),
				true
			);
		}
		request.setNameIdPolicy(policy);
		return request;
	}

	private Saml2Endpoint getACSFromSp(ServiceProviderMetadata sp) {
		Saml2Endpoint endpoint = sp.getServiceProvider().getAssertionConsumerService().get(0);
		for (Saml2Endpoint e : sp.getServiceProvider().getAssertionConsumerService()) {
			if (e.isDefault()) {
				endpoint = e;
			}
		}
		return endpoint;
	}

	public Saml2Assertion assertion(ServiceProviderMetadata sp,
									Saml2IdentityProviderMetadata idp,
									Saml2AuthenticationSaml2Request request,
									String principal,
									Saml2NameId principalFormat) {

		long now = time.millis();
		return new Saml2Assertion()
			.setSigningKey(idp.getSigningKey(), idp.getAlgorithm(), idp.getDigest())
			.setVersion("2.0")
			.setIssueInstant(new DateTime(now))
			.setId("A"+UUID.randomUUID().toString())
			.setIssuer(idp.getEntityId())
			.setSubject(
				new Saml2Subject()
					.setPrincipal(
						new Saml2NameIdPrincipalSaml2()
							.setValue(principal)
							.setFormat(principalFormat)
							.setNameQualifier(sp.getEntityAlias())
							.setSpNameQualifier(sp.getEntityId())
					)
					.addConfirmation(
						new Saml2SubjectConfirmation()
							.setMethod(Saml2SubjectConfirmationMethod.BEARER)
							.setConfirmationData(
								new Saml2SubjectConfirmationData()
									.setInResponseTo(request != null ? request.getId() : null)
									//we don't set NotBefore. Gets rejected.
									//.setNotBefore(new DateTime(now - NOT_BEFORE))
									.setNotOnOrAfter(new DateTime(now + NOT_AFTER))
									.setRecipient(
										request != null ?
											request.getAssertionConsumerService().getLocation() :
											getACSFromSp(sp).getLocation()
									)
							)
					)


			)
			.setConditions(
				new Saml2Conditions()
					.setNotBefore(new DateTime(now - NOT_BEFORE))
					.setNotOnOrAfter(new DateTime(now + NOT_AFTER))
					.addCriteria(
						new Saml2AudienceRestriction()
							.addAudience(sp.getEntityId())

					)
			)
			.addAuthenticationStatement(
				new Saml2AuthenticationStatement()
					.setAuthInstant(new DateTime(now))
					.setSessionIndex("IDX"+UUID.randomUUID().toString())
					.setSessionNotOnOrAfter(new DateTime(now + SESSION_NOT_AFTER))

			);

	}

	public Saml2ResponseSaml2 response(Saml2AuthenticationSaml2Request authn,
									   Saml2Assertion assertion,
									   ServiceProviderMetadata recipient,
									   Saml2IdentityProviderMetadata local) {
		Saml2ResponseSaml2 result = new Saml2ResponseSaml2()
			.setAssertions(asList(assertion))
			.setId("RP"+UUID.randomUUID().toString())
			.setInResponseTo(authn != null ? authn.getId() : null)
			.setStatus(new Saml2Status().setCode(Saml2StatusCode.UNKNOWN_STATUS))
			.setIssuer(new Saml2Issuer().setValue(local.getEntityId()))
			.setSigningKey(local.getSigningKey(), local.getAlgorithm(), local.getDigest())
			.setIssueInstant(new DateTime())
			.setStatus(new Saml2Status().setCode(Saml2StatusCode.SUCCESS))
			.setVersion("2.0");
		Saml2Endpoint acs = (authn != null ? authn.getAssertionConsumerService() : null);
		if (acs == null) {
			acs = getPreferredACS(recipient.getServiceProvider().getAssertionConsumerService(), asList(Saml2BindingType.POST));
		}
		if (acs != null) {
			result.setDestination(acs.getLocation());
		}
		return result;
	}

	public Saml2Endpoint getPreferredACS(List<Saml2Endpoint> eps,
										 List<Saml2BindingType> preferred) {
		if (eps == null || eps.isEmpty()) {
			return null;
		}
		Saml2Endpoint result = null;
		for (Saml2Endpoint e : eps) {
			if (e.isDefault() && preferred.contains(e.getBinding().getType())) {
				result = e;
				break;
			}
		}
		for (Saml2Endpoint e : (result == null ? eps : Collections.<Saml2Endpoint>emptyList())) {
			if (e.isDefault()) {
				result = e;
				break;
			}
		}
		for (Saml2Endpoint e : (result == null ? eps : Collections.<Saml2Endpoint>emptyList())) {
			if (preferred.contains(e.getBinding().getType())) {
				result = e;
				break;
			}
		}
		if (result == null) {
			result = eps.get(0);
		}
		return result;
	}

	public Saml2LogoutSaml2Request logoutRequest(Saml2Metadata<? extends Saml2Metadata> recipient,
												 Saml2Metadata<? extends Saml2Metadata> local,
												 Saml2NameIdPrincipalSaml2 principal) {


		Saml2LogoutSaml2Request result = new Saml2LogoutSaml2Request()
			.setId("LRQ"+UUID.randomUUID().toString())
			.setDestination(getSingleLogout(recipient.getSsoProviders().get(0).getSingleLogoutService()))
			.setIssuer(new Saml2Issuer().setValue(local.getEntityId()))
			.setIssueInstant(DateTime.now())
			.setNameId(principal)
			.setSigningKey(local.getSigningKey(), local.getAlgorithm(), local.getDigest());

		return result;
	}

	public Saml2Endpoint getSingleLogout(List<Saml2Endpoint> logoutService) {
		if (logoutService == null || logoutService.isEmpty()) {
			return null;
		}
		List<Saml2Endpoint> eps = logoutService;
		Saml2Endpoint result = null;
		for (Saml2Endpoint e : eps) {
			if (e.isDefault()) {
				result = e;
				break;
			}
			else if (Saml2BindingType.REDIRECT == e.getBinding().getType()) {
				result = e;
				break;
			}
		}
		if (result == null) {
			result = eps.get(0);
		}
		return result;
	}

	public Saml2LogoutResponseSaml2 logoutResponse(Saml2LogoutSaml2Request request,
												   Saml2IdentityProviderMetadata recipient,
												   ServiceProviderMetadata local) {
		return logoutResponse(
			request,
			recipient,
			local,
			getSingleLogout(recipient.getIdentityProvider().getSingleLogoutService())
		);
	}

	public Saml2LogoutResponseSaml2 logoutResponse(Saml2LogoutSaml2Request request,
												   Saml2Metadata<? extends Saml2Metadata> recipient,
												   Saml2Metadata<? extends Saml2Metadata> local,
												   Saml2Endpoint destination) {

		return new Saml2LogoutResponseSaml2()
			.setId("LRP"+UUID.randomUUID().toString())
			.setInResponseTo(request != null ? request.getId() : null)
			.setDestination(destination != null ? destination.getLocation() : null)
			.setStatus(new Saml2Status().setCode(Saml2StatusCode.SUCCESS))
			.setIssuer(new Saml2Issuer().setValue(local.getEntityId()))
			.setSigningKey(local.getSigningKey(), local.getAlgorithm(), local.getDigest())
			.setIssueInstant(new DateTime())
			.setVersion("2.0");
	}

	public Saml2LogoutResponseSaml2 logoutResponse(Saml2LogoutSaml2Request request,
												   ServiceProviderMetadata recipient,
												   Saml2IdentityProviderMetadata local) {
		return logoutResponse(
			request,
			recipient,
			local,
			getSingleLogout(recipient.getServiceProvider().getSingleLogoutService())
		);
	}

	public static Map<String, String> queryParams(URI url) throws UnsupportedEncodingException {
		Map<String, String> queryPairs = new LinkedHashMap<>();
		String query = url.getQuery();
		String[] pairs = query.split("&");
		for (String pair : pairs) {
			int idx = pair.indexOf("=");
			queryPairs.put(
				UriUtils.decode(pair.substring(0, idx), UTF_8.name()),
				UriUtils.decode(pair.substring(idx + 1), UTF_8.name())
			);
		}
		return queryPairs;
	}
}
