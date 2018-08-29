package org.springframework.security.saml.provider.config;

import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.provider.SamlServerConfiguration;

public class ThreadLocalSamlConfigurationRepository implements SamlConfigurationRepository {

    private static InheritableThreadLocal<SamlServerConfiguration> threadLocal = new InheritableThreadLocal<>();

    private final SamlServerConfiguration initialValue;

    public ThreadLocalSamlConfigurationRepository(SamlServerConfiguration initialValue) {
        this.initialValue = initialValue;
    }

    @Override
    public SamlServerConfiguration getServerConfiguration() {
        SamlServerConfiguration result = threadLocal.get();
        if (result == null) {
            try {
                result = initialValue.clone();
            } catch (CloneNotSupportedException e) {
                throw new SamlException(e);
            }
        }
        return result;
    }

    void setServerConfiguration(SamlServerConfiguration configuration) {
        threadLocal.set(configuration);
    }

    public void reset() {
        threadLocal.remove();
    }
}
