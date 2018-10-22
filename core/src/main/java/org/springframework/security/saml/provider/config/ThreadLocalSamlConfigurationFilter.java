package org.springframework.security.saml.provider.config;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml.registration.HostedIdentityProviderConfiguration;
import org.springframework.security.saml.registration.HostedServiceProviderConfiguration;
import org.springframework.security.saml.registration.SamlServerConfiguration;
import org.springframework.web.filter.OncePerRequestFilter;

import static org.springframework.util.StringUtils.hasText;

public class ThreadLocalSamlConfigurationFilter extends OncePerRequestFilter {

	private final ThreadLocalSamlConfigurationRepository repository;
	private boolean includeStandardPortsInUrl = false;

	public ThreadLocalSamlConfigurationFilter(ThreadLocalSamlConfigurationRepository repository) {
		this.repository = repository;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
		throws ServletException, IOException {
		SamlServerConfiguration configuration = getConfiguration(request);
		//allow for dynamic host paths
		try {
			repository.setServerConfiguration(configuration);
			filterChain.doFilter(request, response);
		} finally {
			repository.reset();
		}
	}

	protected SamlServerConfiguration getConfiguration(HttpServletRequest request) {
		SamlServerConfiguration result =  repository.getServerConfiguration(request);
		String basePath = getBasePath(request);

		HostedIdentityProviderConfiguration identityProvider = result.getIdentityProvider();
		if (identityProvider!=null && !hasText(identityProvider.getBasePath())) {
			identityProvider = new HostedIdentityProviderConfiguration(
				identityProvider.getPrefix(),
				basePath,
				identityProvider.getAlias(),
				identityProvider.getEntityId(),
				identityProvider.isSignMetadata(),
				identityProvider.isSignAssertions(),
				identityProvider.isWantRequestsSigned(),
				identityProvider.getMetadata(),
				identityProvider.getKeys(),
				identityProvider.getDefaultSigningAlgorithm(),
				identityProvider.getDefaultDigest(),
				identityProvider.getNameIds(),
				identityProvider.isSingleLogoutEnabled(),
				identityProvider.getProviders(),
				identityProvider.isEncryptAssertions(),
				identityProvider.getKeyEncryptionAlgorithm(),
				identityProvider.getDataEncryptionAlgorithm(),
				identityProvider.getNotOnOrAfter(),
				identityProvider.getNotBefore(),
				identityProvider.getSessionNotOnOrAfter()
			);
		}
		HostedServiceProviderConfiguration serviceProvider = result.getServiceProvider();
		if (serviceProvider!=null && !hasText(serviceProvider.getBasePath())) {

			serviceProvider = new HostedServiceProviderConfiguration(
				serviceProvider.getPrefix(),
				basePath,
				serviceProvider.getAlias(),
				serviceProvider.getEntityId(),
				serviceProvider.isSignMetadata(),
				serviceProvider.getMetadata(),
				serviceProvider.getKeys(),
				serviceProvider.getDefaultSigningAlgorithm(),
				serviceProvider.getDefaultDigest(),
				serviceProvider.getNameIds(),
				serviceProvider.isSingleLogoutEnabled(),
				serviceProvider.getProviders(),
				serviceProvider.isSignRequests(),
				serviceProvider.isWantAssertionsSigned()
			);
		}

		return new SamlServerConfiguration(
			serviceProvider,
			identityProvider,
			result.getNetwork()
		);
	}

	protected String getBasePath(HttpServletRequest request) {
		boolean includePort = true;
		if (443 == request.getServerPort() && "https".equals(request.getScheme())) {
			includePort = isIncludeStandardPortsInUrl();
		}
		else if (80 == request.getServerPort() && "http".equals(request.getScheme())) {
			includePort = isIncludeStandardPortsInUrl();
		}
		return request.getScheme() +
			"://" +
			request.getServerName() +
			(includePort ? (":" + request.getServerPort()) : "") +
			request.getContextPath();
	}

	public boolean isIncludeStandardPortsInUrl() {
		return includeStandardPortsInUrl;
	}

	public ThreadLocalSamlConfigurationFilter setIncludeStandardPortsInUrl(boolean includeStandardPortsInUrl) {
		this.includeStandardPortsInUrl = includeStandardPortsInUrl;
		return this;
	}
}
