package org.springframework.security.saml.provider.config;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static java.util.Arrays.asList;
import static org.springframework.util.StringUtils.hasText;
import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.web.filter.OncePerRequestFilter;

public class ServletSamlConfigurationFilter extends OncePerRequestFilter {

    private final ThreadLocalSamlConfigurationRepository repository;
    private final SamlConfigurationRepository source;

    public ServletSamlConfigurationFilter(ThreadLocalSamlConfigurationRepository repository, SamlConfigurationRepository source) {
        this.repository = repository;
        this.source = source;
    }


    protected SamlServerConfiguration getConfiguration(HttpServletRequest request) {
        SamlServerConfiguration result = null;
        if (source != null) {
            try {
                result = (SamlServerConfiguration) source.getServerConfiguration().clone();
            } catch (CloneNotSupportedException e) {
                throw new SamlException(e);
            }
        }
        return result;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        SamlServerConfiguration configuration = getConfiguration(request);
        //allow for dynamic host paths
        if (configuration != null) {
            for (LocalProviderConfiguration config : asList(
                configuration.getIdentityProvider(),
                configuration.getServiceProvider())
                ) {
                if (config != null && !hasText(config.getBasePath())) {
                    config.setBasePath(getBasePath(request));
                }
            }
        }
        try {
            repository.setServerConfiguration(configuration);
            filterChain.doFilter(request, response);
        } finally {
            repository.reset();
        }
    }

    private String getBasePath(HttpServletRequest request) {
        return request == null ?
            null :
            request.getScheme() +
                "://" +
                request.getServerName() +
                ":" +
                request.getServerPort() +
                request.getContextPath();
    }
}
