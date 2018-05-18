/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package sample.config;

import java.time.Clock;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml.MetadataResolver;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.spi.DefaultMetadataCache;
import org.springframework.security.saml.spi.DefaultMetadataResolver;
import org.springframework.security.saml.spi.DefaultSamlTransformer;
import org.springframework.security.saml.spi.DefaultValidator;
import org.springframework.security.saml.spi.Defaults;
import org.springframework.security.saml.spi.SpringSecuritySaml;
import org.springframework.security.saml.spi.opensaml.OpenSamlConfiguration;
import org.springframework.security.saml.util.Network;

@Configuration
public class SamlConfiguration {

    @Bean
    public Clock time() {
        return Clock.systemUTC();
    }

    @Bean
    public SamlTransformer transformer() {
        return new DefaultSamlTransformer(implementation());
    }

    @Bean
    public SamlValidator validator() {
        return new DefaultValidator(implementation());
    }

    @Bean
    public Defaults defaults() {
        return new Defaults(time());
    }

    @Bean
    public MetadataResolver resolver() {
        return new DefaultMetadataResolver();
    }

    @Bean
    public Network network() {
        return new Network();
    }

    @Bean
    public DefaultMetadataCache cache() {
        return new DefaultMetadataCache(time(), network());
    }

    @Bean
    public SpringSecuritySaml implementation() {
        return new OpenSamlConfiguration(time());
    }
}
