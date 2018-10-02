package org.springframework.security.saml.provider.config;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.saml.provider.SamlServerConfiguration;

public class ThreadLocalSamlConfigurationRepository
	implements SamlConfigurationRepository<HttpServletRequest> {

	private static InheritableThreadLocal<SamlServerConfiguration> threadLocal = new InheritableThreadLocal<>();

	private final SamlConfigurationRepository initialValueProvider;

	public ThreadLocalSamlConfigurationRepository(SamlConfigurationRepository initialValueProvider) {
		this.initialValueProvider = initialValueProvider;
	}

	@Override
	public SamlServerConfiguration getServerConfiguration(HttpServletRequest request) {
		SamlServerConfiguration result = threadLocal.get();
		if (result == null) {
			result = initialValueProvider.getServerConfiguration(request);
		}
		return result;
	}

	protected void setServerConfiguration(SamlServerConfiguration configuration) {
		if (configuration == null) {
			reset();
		}
		else {
			threadLocal.set(configuration);
		}
	}

	public void reset() {
		threadLocal.remove();
	}

}
