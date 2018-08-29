package org.springframework.security.saml.provider.config;

import org.springframework.security.saml.provider.SamlServerConfiguration;

public class ThreadLocalSamlConfigurationRepository implements SamlConfigurationRepository {

    private static InheritableThreadLocal<SamlServerConfiguration> threadLocal = new InheritableThreadLocal<>();

    @Override
    public SamlServerConfiguration getServerConfiguration() {
        return threadLocal.get();
    }

    void setServerConfiguration(SamlServerConfiguration configuration) {
        threadLocal.set(configuration);
    }

    public void reset() {
        threadLocal.remove();
    }
}
