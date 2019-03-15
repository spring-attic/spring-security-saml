/*
 * Copyright 2002-2018 the original author or authors.
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

package sample.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.provider.config.RotatingKeys;
import org.springframework.security.saml.provider.identity.config.ExternalServiceProviderConfiguration;
import org.springframework.security.saml.provider.identity.config.SamlIdentityProviderSecurityConfiguration;
import org.springframework.security.saml.saml2.metadata.NameId;

import static java.util.Arrays.asList;
import static org.springframework.security.saml.provider.identity.config.SamlIdentityProviderSecurityDsl.identityProvider;
import static org.springframework.security.saml.saml2.encrypt.DataEncryptionMethod.AES128_CBC;
import static org.springframework.security.saml.saml2.encrypt.KeyEncryptionMethod.RSA_1_5;
import static org.springframework.security.saml.saml2.signature.AlgorithmMethod.RSA_SHA512;
import static org.springframework.security.saml.saml2.signature.DigestMethod.SHA512;

@EnableWebSecurity
public class Security {

	@Configuration
	@Order(1)
	public static class SamlSecurity extends SamlIdentityProviderSecurityConfiguration {

		private final BeanConfig beanConfig;
		public SamlSecurity(BeanConfig configuration) {
			super("/saml/dsl-idp-prefix/", configuration);
			this.beanConfig = configuration;
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			String prefix = getPrefix();
			super.configure(http);
			//we want to use the FORM when accessing the SAML SSO endpoint
			http
				.userDetailsService(beanConfig.userDetailsService()).formLogin();

			http.apply(identityProvider())
				.prefix(prefix)
				.useStandardFilters()
				.entityId("spring.security.saml.dsl.id")
				.alias("boot-dsl-idp")
				.signMetadata(true)
				.encryptAssertions(true, RSA_1_5, AES128_CBC)
				.signatureAlgorithms(RSA_SHA512, SHA512)
				.wantRequestsSigned(true)
				.singleLogout(true)
				.nameIds(asList(NameId.EMAIL))
				.rotatingKeys(getKeys())
				.serviceProvider(
					new ExternalServiceProviderConfiguration()
						.setAlias("boot-sample-sp")
						.setLinktext("Spring Security SAML SP/8080")
						.setMetadata("http://localhost:8080/sample-sp/saml/sp/metadata")
						.setSkipSslValidation(true)
				)
			;

		}


		private RotatingKeys getKeys() {
			return new RotatingKeys()
				.setActive(
					new SimpleKey()
						.setName("sample-dsl-idp-key")
						.setPrivateKey("-----BEGIN RSA PRIVATE KEY-----\n" +
							"Proc-Type: 4,ENCRYPTED\n" +
							"DEK-Info: DES-EDE3-CBC,D0A1A612C22782F4\n" +
							"\n" +
							"TlRgdaoc3McGzJ/dk0uGxRXE6GqjS/LkHVOhF/wOXHkl3Phfd/IRkoRRP8FdQIJb\n" +
							"oHEmJKxz1IuqKxJGJS4MbuitoP3iZ921o/xJiTZfIUiVx3OXJeykdzOadKi6inW0\n" +
							"fWx/csydqGoTJIT/2+jlNeagaiXyhwnbMZFJ0xMhox4ieKiCNuzXFGOMggkJ7wSb\n" +
							"2i1ifiBKMrUUevfEfDNa5Vs0PqON8bdnEkHO2SWI/0zI+8pUHCzLgxPUFcRe4RmU\n" +
							"w1l4yH6udGO5kkAObVivKza8UwDnLiNG7xxGGH251iN+UBmTNw4ZMPaXUJ0mgeKK\n" +
							"EFSVLFzJ3P96yverlmx9mBpUDawcQdK5WxNpHohRzYF4OkBtRf6rRjE+/cO7AqVx\n" +
							"DftGjzJtPGj/4HvVTMSKE0a4MtKnI2Z/rCZOoEFLxkIwPdOc7jvoX0yKnIcL3h+2\n" +
							"Xx5Vy1QaTw1o1tgpQvVSg25BLvK1rmjCKPIG44fz3OIi4A6a/A9vpulQhB9kbrO5\n" +
							"bejRWKiWTw9Lf0lqwfDwc/zK2sme5frrlCZWm+jfJt57+LCbRT/lzZRXvtHKlsBz\n" +
							"CutUhWEep9X9QccWLPHUOyTJtQUzZQlEJqWYpbSl6RmCyRLpY//vjO+gviJRTP65\n" +
							"k+E3T89TxdKFkzDznjWT1bjWyhkEGoUv83wOkqNhTTVjyaROKl7i+GVhAJ/Y/KB6\n" +
							"nwlh60MXOoP0bwOhIt4ZX7gLeaCUGJvZ+GEN7r4N1NtR4hq6A5hC6EdXbSAvjALZ\n" +
							"3SeVbuhSqE8/3+OHdblUDgp+MGxqh9qazMIcgtc0xl7YW8Rv0dA8vQ==\n" +
							"-----END RSA PRIVATE KEY-----\n")
						.setPassphrase("dsl-idppassword")
						.setCertificate("-----BEGIN CERTIFICATE-----\n" +
							"MIIClTCCAf4CCQCwAAZcZPlESTANBgkqhkiG9w0BAQsFADCBjjELMAkGA1UEBhMC\n" +
							"VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsG\n" +
							"A1UECgwUU3ByaW5nIFNlY3VyaXR5IFNBTUwxEDAOBgNVBAsMB2RzbC1pZHAxJTAj\n" +
							"BgNVBAMMHGRzbC1pZHAuc3ByaW5nLnNlY3VyaXR5LnNhbWwwHhcNMTgwODMxMTYz\n" +
							"NzExWhcNMjgwODI4MTYzNzExWjCBjjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldh\n" +
							"c2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsGA1UECgwUU3ByaW5nIFNl\n" +
							"Y3VyaXR5IFNBTUwxEDAOBgNVBAsMB2RzbC1pZHAxJTAjBgNVBAMMHGRzbC1pZHAu\n" +
							"c3ByaW5nLnNlY3VyaXR5LnNhbWwwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB\n" +
							"ANVRjTcy/vKdIsynvKqBpnWoP6SduYWvtFU5960MQjlXFgwknPIcIHs1IhwVJY4r\n" +
							"Zdmxr8fzEMm16aQ89IcF4RV3qJYWeLfFta7agzk+sfw2p9AZTcmLViRKzB0ozdtk\n" +
							"q1OQApKrn51NEO4BA+Rx0QbHNP4kVGVGLYBGUNdgtTbXAgMBAAEwDQYJKoZIhvcN\n" +
							"AQELBQADgYEAMGEcvRlg0CdvGdM/iv1EZ3CGTPaiNHPGxyWZTmVV7rRIUzsi4xdt\n" +
							"LcQRDEh5qhdeoCnNRGW/amtDKdq00MqvKXSzKlihej+mgzd9yGCfpQLKtzy3adtw\n" +
							"9nrnoClEDx4XXhHw+3C2DPC2J0t1y5PxAnYwIkxJe4kV1nukSHcxZVQ=\n" +
							"-----END CERTIFICATE-----")
				);
		}
	}

	@Configuration
	public class AppSecurity extends WebSecurityConfigurerAdapter {

		private final BeanConfig beanConfig;

		public AppSecurity(BeanConfig beanConfig) {
			this.beanConfig = beanConfig;
		}


		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.antMatcher("/**")
				.csrf().disable()
				.authorizeRequests()
				.antMatchers("/**").authenticated()
				.and()
				.userDetailsService(beanConfig.userDetailsService()).formLogin()
			;


		}
	}

}
