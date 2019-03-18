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
package org.springframework.security.saml.samples;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml.configuration.ExternalIdentityProviderConfiguration;
import org.springframework.security.saml.provider.HostedServiceProvider;
import org.springframework.security.saml.model.key.KeyData;
import org.springframework.security.saml.model.key.KeyType;
import org.springframework.security.saml.model.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.model.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.serviceprovider.ServiceProviderResolver;
import org.springframework.security.saml.serviceprovider.metadata.ServiceProviderMetadataResolver;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("SAML Service Provider Metadata")
public class ServiceProviderMetadataTests extends AbstractServiceProviderTestBase {

	@Autowired(required = false)
	ServiceProviderMetadataResolver metadataResolver;

	@Autowired(required = false)
	ServiceProviderResolver spResolver;
	private ExternalIdentityProviderConfiguration.Builder remoteTrustCheckMetadata =
		ExternalIdentityProviderConfiguration.builder()
			.alias("metadata-trust-check")
			.linktext("Remote Trust Check Metadata")
			.metadataTrustCheck(true)
			.verificationKeys(asList(
				new KeyData(
					"trust",
					null,
					METADATA_TRUST_CHECK_KEY,
					null,
					KeyType.SIGNING
				)
			))
			.metadata(METADATA_TRUST_CHECK);

	@SpringBootConfiguration
	@EnableAutoConfiguration
	@ComponentScan(basePackages = "org/springframework/security/saml/samples")
	public static class SpringBootApplicationTestConfig {
	}

	@Test
	@DisplayName("SSO logout endpoints are present in metadata")
	void singleLogoutMetadata() throws Exception {
		mockConfig(builder -> builder.singleLogoutEnabled(true));
		ServiceProviderMetadata spm = getServiceProviderMetadata();
		assertThat(spm.getServiceProvider().getSingleLogoutService(), not(empty()));
	}

	@Test
	@DisplayName("SSO logout endpoints are disabled")
	void singleLogoutDisabledMetadata() throws Exception {
		mockConfig(builder -> builder.singleLogoutEnabled(false));
		ServiceProviderMetadata spm = getServiceProviderMetadata();
		assertThat(spm.getServiceProvider().getSingleLogoutService(), containsInAnyOrder());
	}


	@Test
	@DisplayName("fetch service provider metadata")
	void testGetMetadata() throws Exception {
		ServiceProviderMetadata metadata = getServiceProviderMetadata();
		assertNotNull(metadata);
		assertThat(metadata.getEntityId(), equalTo("spring.security.saml.sp.id"));
	}

	@Test
	@DisplayName("service Provider entity-id is generated")
	void generateSpEntityId() throws Exception {
		mockConfig(builder -> builder.entityId(null));
		ServiceProviderMetadata metadata = getServiceProviderMetadata();
		assertNotNull(metadata);
		assertThat(metadata.getEntityId(), equalTo("http://localhost"));
	}

	@Test
	@DisplayName("service provider entity-id is based on configured base path")
	void generateSpEntityIdFromBasePath() throws Exception {
		mockConfig(builder -> builder.entityId(null).basePath("http://some.other.host:8080/sample-sp"));
		ServiceProviderMetadata metadata = getServiceProviderMetadata();
		assertNotNull(metadata);
		assertThat(metadata.getEntityId(), equalTo("http://some.other.host:8080/sample-sp"));
		assertThat(metadata.getEntityAlias(), equalTo("some.other.host"));
	}

	@Test
	@DisplayName("remote party metadata contains both IDP and SP descriptors")
	void parseDualRemoteMetadata() throws Exception {
		final List<ExternalIdentityProviderConfiguration> providers =
			bootConfiguration.getServiceProvider().getProviders().stream()
				.map(p -> p.toExternalIdentityProviderConfiguration())
				.collect(Collectors.toList());
		providers.add(
			ExternalIdentityProviderConfiguration.builder()
				.alias("dual")
				.linktext("Dual IDP/SP Metadata")
				.metadata(IDP_DUAL_METADATA)
				.build()
		);
		mockConfig(builder -> builder.providers(providers));
		mockMvc.perform(
			get("/saml/sp/select")
				.accept(MediaType.TEXT_HTML)
		)
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("<h1>Select an Identity Provider</h1>")))
			.andExpect(content().string(containsString("Dual IDP/SP Metadata")))
			.andReturn();
	}

	@Test
	@DisplayName("signed remote metadata is verified through signature")
	void remoteMetadataTrustCheck() throws Exception {
		final List<ExternalIdentityProviderConfiguration> providers =
			bootConfiguration.getServiceProvider().getProviders().stream()
				.map(p -> p.toExternalIdentityProviderConfiguration())
				.collect(Collectors.toList());
		providers.add(remoteTrustCheckMetadata.build());
		mockConfig(builder -> builder.providers(providers));
		mockMvc.perform(
			get("/saml/sp/select")
				.accept(MediaType.TEXT_HTML)
		)
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("<h1>Select an Identity Provider</h1>")))
			.andExpect(content().string(containsString("Remote Trust Check Metadata")))
			.andReturn();
	}

	@Test
	@DisplayName("signed remote metadata fails signature verification")
	void remoteMetadataTrustCheckFails() throws Exception {
		final List<ExternalIdentityProviderConfiguration> providers =
			bootConfiguration.getServiceProvider().getProviders().stream()
				.map(p -> p.toExternalIdentityProviderConfiguration())
				.collect(Collectors.toList());
		providers.add(
			remoteTrustCheckMetadata
				.verificationKeys(asList(SimpleSamlPhpTestKeys.getSimpleSamlPhpKeyData())) //incorrect key
				.build()
		);
		mockConfig(builder -> builder.providers(providers));
		mockMvc.perform(
			get("/saml/sp/select")
				.accept(MediaType.TEXT_HTML)
		)
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("<h1>Select an Identity Provider</h1>")))
			.andExpect(content().string(not(containsString("Remote Trust Check Metadata"))))
			.andReturn();
	}

	@DisplayName("static keys get added to remote provider's metadata")
	@Test
	void staticKeysTest() throws Exception {
		assertNotNull(metadataResolver);
		assertNotNull(spResolver);

		final List<ExternalIdentityProviderConfiguration> providers =
			bootConfiguration.getServiceProvider().getProviders().stream()
				.map(p -> p.toExternalIdentityProviderConfiguration())
				.collect(Collectors.toList());
		providers.add(remoteTrustCheckMetadata
			.addVerificationKey(SimpleSamlPhpTestKeys.getSimpleSamlPhpKeyData())
			.build()
		);
		mockConfig(builder -> builder.providers(providers));

		MockHttpServletRequest request = new MockHttpServletRequest();
		HostedServiceProvider provider = spResolver.getServiceProvider(request);
		Map<ExternalIdentityProviderConfiguration, IdentityProviderMetadata> idps =
			metadataResolver.getIdentityProviders(provider.getConfiguration());
		Map.Entry<ExternalIdentityProviderConfiguration, IdentityProviderMetadata> entry = idps.entrySet()
			.stream()
			.filter(
				e -> e.getValue().getEntityId().equals("login.run.pivotal.io")
			)
			.findFirst()
			.orElse(null);
		assertNotNull(entry);
		IdentityProviderMetadata metadata = entry.getValue();
		List<KeyData> keys = metadata.getIdentityProvider().getKeys();
		KeyData staticKey = keys.stream()
			.filter(
				k -> SimpleSamlPhpTestKeys.getSimpleSamlPhpKeyData().getCertificate().equals(k.getCertificate())
			)
			.findFirst()
			.orElse(null);
		assertNotNull(staticKey);
	}


	private final String IDP_DUAL_METADATA =
		"<ns3:EntityDescriptor xmlns:ns3=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns=\"http://www.w3.org/2000/09/xmldsig#\"\n" +
			"                      xmlns:ns2=\"http://www.w3.org/2001/04/xmlenc#\" xmlns:ns4=\"urn:oasis:names:tc:SAML:2.0:assertion\"\n" +
			"                      ID=\"S9a4982e5-0588-4a51-8ea9-c7bb5a62dc14\" entityID=\"Zalar_73_Test\">\n" +
			"    <ns3:IDPSSODescriptor WantAuthnRequestsSigned=\"true\"\n" +
			"                          protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
			"        <ns3:KeyDescriptor use=\"signing\">\n" +
			"            <KeyInfo>\n" +
			"                <KeyName>Zalar_73_Test</KeyName>\n" +
			"                <X509Data>\n" +
			"                    <X509Certificate>MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMC\n" +
			"VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsG\n" +
			"A1UECgwUU3ByaW5nIFNlY3VyaXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQD\n" +
			"DBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAeFw0xODA1MTQxNDMwNDRaFw0yODA1\n" +
			"MTExNDMwNDRaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjES\n" +
			"MBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkgU0FN\n" +
			"TDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1s\n" +
			"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRu7/EI0BlNzMEBFVAcbx+lLos\n" +
			"vzIWU+01dGTY8gBdhMQNYKZ92lMceo2CuVJ66cUURPym3i7nGGzoSnAxAre+0YIM\n" +
			"+U0razrWtAUE735bkcqELZkOTZLelaoOztmWqRbe5OuEmpewH7cx+kNgcVjdctOG\n" +
			"y3Q6x+I4qakY/9qhBQIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAAeViTvHOyQopWEi\n" +
			"XOfI2Z9eukwrSknDwq/zscR0YxwwqDBMt/QdAODfSwAfnciiYLkmEjlozWRtOeN+\n" +
			"qK7UFgP1bRl5qksrYX5S0z2iGJh0GvonLUt3e20Ssfl5tTEDDnAEUMLfBkyaxEHD\n" +
			"RZ/nbTJ7VTeZOSyRoVn5XHhpuJ0B</X509Certificate>\n" +
			"                </X509Data>\n" +
			"            </KeyInfo>\n" +
			"        </ns3:KeyDescriptor>\n" +
			"        <ns3:KeyDescriptor use=\"encryption\">\n" +
			"            <KeyInfo>\n" +
			"                <KeyName>Zalar_73_Test</KeyName>\n" +
			"                <X509Data>\n" +
			"                    <X509Certificate>MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMC\n" +
			"VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsG\n" +
			"A1UECgwUU3ByaW5nIFNlY3VyaXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQD\n" +
			"DBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAeFw0xODA1MTQxNDMwNDRaFw0yODA1\n" +
			"MTExNDMwNDRaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjES\n" +
			"MBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkgU0FN\n" +
			"TDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1s\n" +
			"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRu7/EI0BlNzMEBFVAcbx+lLos\n" +
			"vzIWU+01dGTY8gBdhMQNYKZ92lMceo2CuVJ66cUURPym3i7nGGzoSnAxAre+0YIM\n" +
			"+U0razrWtAUE735bkcqELZkOTZLelaoOztmWqRbe5OuEmpewH7cx+kNgcVjdctOG\n" +
			"y3Q6x+I4qakY/9qhBQIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAAeViTvHOyQopWEi\n" +
			"XOfI2Z9eukwrSknDwq/zscR0YxwwqDBMt/QdAODfSwAfnciiYLkmEjlozWRtOeN+\n" +
			"qK7UFgP1bRl5qksrYX5S0z2iGJh0GvonLUt3e20Ssfl5tTEDDnAEUMLfBkyaxEHD\n" +
			"RZ/nbTJ7VTeZOSyRoVn5XHhpuJ0B</X509Certificate>\n" +
			"                </X509Data>\n" +
			"            </KeyInfo>\n" +
			"        </ns3:KeyDescriptor>\n" +
			"        <ns3:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\"\n" +
			"                                 Location=\"https://testportal.zalar.com/saml2/idp/slo\"/>\n" +
			"        <ns3:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"\n" +
			"                                 Location=\"https://testportal.zalar.com/saml2/idp/slo\"/>\n" +
			"        <ns3:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\"\n" +
			"                                 Location=\"https://testportal.zalar.com/saml2/idp/slo\"/>\n" +
			"        <ns3:ManageNameIDService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"\n" +
			"                                 Location=\"https://testportal.zalar.com/saml2/idp/mni\"/>\n" +
			"        <ns3:ManageNameIDService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:SOAP\"\n" +
			"                                 Location=\"https://testportal.zalar.com/saml2/idp/mni\"/>\n" +
			"        <ns3:ManageNameIDService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\"\n" +
			"                                 Location=\"https://testportal.zalar.com/saml2/idp/mni\"/>\n" +
			"        <ns3:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\"\n" +
			"                                 Location=\"https://testportal.zalar.com/saml2/idp/sso\"/>\n" +
			"        <ns3:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"\n" +
			"                                 Location=\"https://testportal.zalar.com/saml2/idp/sso\"/>\n" +
			"        <ns3:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:SOAP\"\n" +
			"                                 Location=\"https://testportal.zalar.com/saml2/idp/sso\"/>\n" +
			"        <ns3:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\"\n" +
			"                                 Location=\"https://testportal.zalar.com/saml2/idp/sso\"/>\n" +
			"    </ns3:IDPSSODescriptor>\n" +
			"    <ns3:SPSSODescriptor AuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
			"        <ns3:KeyDescriptor use=\"signing\">\n" +
			"            <KeyInfo>\n" +
			"                <KeyName>Zalar_73_Test</KeyName>\n" +
			"                <X509Data>\n" +
			"                    <X509Certificate>MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMC\n" +
			"VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsG\n" +
			"A1UECgwUU3ByaW5nIFNlY3VyaXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQD\n" +
			"DBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAeFw0xODA1MTQxNDMwNDRaFw0yODA1\n" +
			"MTExNDMwNDRaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjES\n" +
			"MBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkgU0FN\n" +
			"TDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1s\n" +
			"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRu7/EI0BlNzMEBFVAcbx+lLos\n" +
			"vzIWU+01dGTY8gBdhMQNYKZ92lMceo2CuVJ66cUURPym3i7nGGzoSnAxAre+0YIM\n" +
			"+U0razrWtAUE735bkcqELZkOTZLelaoOztmWqRbe5OuEmpewH7cx+kNgcVjdctOG\n" +
			"y3Q6x+I4qakY/9qhBQIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAAeViTvHOyQopWEi\n" +
			"XOfI2Z9eukwrSknDwq/zscR0YxwwqDBMt/QdAODfSwAfnciiYLkmEjlozWRtOeN+\n" +
			"qK7UFgP1bRl5qksrYX5S0z2iGJh0GvonLUt3e20Ssfl5tTEDDnAEUMLfBkyaxEHD\n" +
			"RZ/nbTJ7VTeZOSyRoVn5XHhpuJ0B</X509Certificate>\n" +
			"                </X509Data>\n" +
			"            </KeyInfo>\n" +
			"        </ns3:KeyDescriptor>\n" +
			"        <ns3:KeyDescriptor use=\"encryption\">\n" +
			"            <KeyInfo>\n" +
			"                <KeyName>Zalar_73_Test</KeyName>\n" +
			"                <X509Data>\n" +
			"                    <X509Certificate>MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMC\n" +
			"VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsG\n" +
			"A1UECgwUU3ByaW5nIFNlY3VyaXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQD\n" +
			"DBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAeFw0xODA1MTQxNDMwNDRaFw0yODA1\n" +
			"MTExNDMwNDRaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjES\n" +
			"MBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkgU0FN\n" +
			"TDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1s\n" +
			"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRu7/EI0BlNzMEBFVAcbx+lLos\n" +
			"vzIWU+01dGTY8gBdhMQNYKZ92lMceo2CuVJ66cUURPym3i7nGGzoSnAxAre+0YIM\n" +
			"+U0razrWtAUE735bkcqELZkOTZLelaoOztmWqRbe5OuEmpewH7cx+kNgcVjdctOG\n" +
			"y3Q6x+I4qakY/9qhBQIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAAeViTvHOyQopWEi\n" +
			"XOfI2Z9eukwrSknDwq/zscR0YxwwqDBMt/QdAODfSwAfnciiYLkmEjlozWRtOeN+\n" +
			"qK7UFgP1bRl5qksrYX5S0z2iGJh0GvonLUt3e20Ssfl5tTEDDnAEUMLfBkyaxEHD\n" +
			"RZ/nbTJ7VTeZOSyRoVn5XHhpuJ0B</X509Certificate>\n" +
			"                </X509Data>\n" +
			"            </KeyInfo>\n" +
			"        </ns3:KeyDescriptor>\n" +
			"        <ns3:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"\n" +
			"                                 Location=\"https://testportal.zalar.com/saml2/sp/slo\"/>\n" +
			"        <ns3:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\"\n" +
			"                                 Location=\"https://testportal.zalar.com/saml2/sp/slo\"/>\n" +
			"        <ns3:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"\n" +
			"                                      Location=\"https://testportal.zalar.com/saml2/sp/acs\" index=\"0\"\n" +
			"                                      isDefault=\"true\"/>\n" +
			"        <ns3:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:PAOS\"\n" +
			"                                      Location=\"https://testportal.zalar.com/saml2/sp/acs\" index=\"2\"/>\n" +
			"    </ns3:SPSSODescriptor>\n" +
			"    <ns3:Organization>\n" +
			"        <ns3:OrganizationName xml:lang=\"English\">Zalar</ns3:OrganizationName>\n" +
			"        <ns3:OrganizationDisplayName xml:lang=\"English\">Zalar</ns3:OrganizationDisplayName>\n" +
			"        <ns3:OrganizationURL>http://www.zalar.com</ns3:OrganizationURL>\n" +
			"    </ns3:Organization>\n" +
			"    <ns3:ContactPerson contactType=\"administrative\">\n" +
			"        <ns3:Company>Zalar</ns3:Company>\n" +
			"        <ns3:GivenName>Firstname</ns3:GivenName>\n" +
			"        <ns3:SurName>Lastname</ns3:SurName>\n" +
			"        <ns3:EmailAddress>firstname.lastname@zalar.com</ns3:EmailAddress>\n" +
			"    </ns3:ContactPerson>\n" +
			"</ns3:EntityDescriptor>";

	private static String METADATA_TRUST_CHECK =
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"login.run.pivotal.io\" entityID=\"login.run.pivotal.io\"><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><ds:Reference URI=\"#login.run.pivotal.io\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>cayGaIpGtYkEXMr0g+scVayzxMI=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>EPu6XnPsdMNNY4fuQczAdGB8029i/t+7tZ2w6xaX1WzutRji76PL2e6zfiZvcBGRrcPYmqVJZC6BorBcvMCIVxE+MxKWp4JE9qsQUMoXGpovbBmiKzMfqaO+lcusCmX6CRyqni6P75L1Sff2j31Sp/QxgXkA3ZHvrcaNynMCWdYaqFUuk/L44CI3FllceGlmWDNEM7gPIEYAlQ6A0ct7y5+Dj+aZxDofS8bTCR3dgf4fw6+gu2Cxf+zbSflQ2kT4jTW0GBsOJ6NBZZCP5f7+WCTWD4YFGSbCk/KisM/FS7i7seedoTJplYLyn+2YYUO1xKnFF8wNL5Uqi92lC1hgGw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDaDCCAlACCQDFsMECzdtetjANBgkqhkiG9w0BAQUFADB2MQswCQYDVQQGEwJVUzETMBEGA1UE\n" +
			"CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEfMB0GA1UECgwWUGl2b3RhbCBT\n" +
			"b2Z0d2FyZSwgSW5jLjEZMBcGA1UEAwwQKi5ydW4ucGl2b3RhbC5pbzAeFw0xNTA5MDIyMzIwMDla\n" +
			"Fw0xODA5MDEyMzIwMDlaMHYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYD\n" +
			"VQQHDA1TYW4gRnJhbmNpc2NvMR8wHQYDVQQKDBZQaXZvdGFsIFNvZnR3YXJlLCBJbmMuMRkwFwYD\n" +
			"VQQDDBAqLnJ1bi5waXZvdGFsLmlvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyz8C\n" +
			"OS7PJbmziNx1H2tpwSuDSX5ThqasDk/7LZ9FG8s/Zu8IqGQvswoGYx3CWgSaNbVA+Oj9zo7awoao\n" +
			"CLCVfU82O3RxH/gNRJQLwBVlgVys5n9UQ2xmTRMOcCTpR5d/zW4jCBgL4q2hjntgDbQNnQKJExgt\n" +
			"CGZJOQOFzsW3iG5NPfcAj+FPseVfD96I2OG3uxFPmO2Ov/EE7Hid6lETdNkXXEB2SxIebNgr03Dj\n" +
			"l6rFXTTdBXhi9gb+EQSZfbETsOHIDYIMLj0SpJvRcbA+7M4/Vynoxlv+/kICqFjjNATfOrqz7xoU\n" +
			"/VlMn1Z3op3cW8GH3iNHvGfIO7sdy2G0gQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQCq3PQDcIss\n" +
			"cIS1Dq++d1dD4vkGt+8IzYz+ijOLECyXsSm7+b4L+CVinFZ9eF99PLlvvJZ8+zA7NfM1wRpjpdKp\n" +
			"0xLTss8yBDHcZkgwvDrH8aTwUtq8gO67wY3JuWBxjTsnoAPbH8zInkHeolCUSobPxAx9XHqbAxfu\n" +
			"a8HJjDihi+cJYEb5lPSpvY5ytcPG9JAXAHQ6aalpJjkyB+eaGRYi8s5Ejr3luI3nzJEzfUj5y0fc\n" +
			"FTv9CtDt9VfblSuHdRw4uFwat5e1Fb7LtEjATi4cKaG1+zZ80QyuChfC08for83TeQgjq7TA10FA\n" +
			"kKe5nrXyHOORz+ttXkYkp5uEBhpZ</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"false\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIIDaDCCAlACCQDFsMECzdtetjANBgkqhkiG9w0BAQUFADB2MQswCQYDVQQGEwJVUzETMBEGA1UE\n" +
			"CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEfMB0GA1UECgwWUGl2b3RhbCBT\n" +
			"b2Z0d2FyZSwgSW5jLjEZMBcGA1UEAwwQKi5ydW4ucGl2b3RhbC5pbzAeFw0xNTA5MDIyMzIwMDla\n" +
			"Fw0xODA5MDEyMzIwMDlaMHYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYD\n" +
			"VQQHDA1TYW4gRnJhbmNpc2NvMR8wHQYDVQQKDBZQaXZvdGFsIFNvZnR3YXJlLCBJbmMuMRkwFwYD\n" +
			"VQQDDBAqLnJ1bi5waXZvdGFsLmlvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyz8C\n" +
			"OS7PJbmziNx1H2tpwSuDSX5ThqasDk/7LZ9FG8s/Zu8IqGQvswoGYx3CWgSaNbVA+Oj9zo7awoao\n" +
			"CLCVfU82O3RxH/gNRJQLwBVlgVys5n9UQ2xmTRMOcCTpR5d/zW4jCBgL4q2hjntgDbQNnQKJExgt\n" +
			"CGZJOQOFzsW3iG5NPfcAj+FPseVfD96I2OG3uxFPmO2Ov/EE7Hid6lETdNkXXEB2SxIebNgr03Dj\n" +
			"l6rFXTTdBXhi9gb+EQSZfbETsOHIDYIMLj0SpJvRcbA+7M4/Vynoxlv+/kICqFjjNATfOrqz7xoU\n" +
			"/VlMn1Z3op3cW8GH3iNHvGfIO7sdy2G0gQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQCq3PQDcIss\n" +
			"cIS1Dq++d1dD4vkGt+8IzYz+ijOLECyXsSm7+b4L+CVinFZ9eF99PLlvvJZ8+zA7NfM1wRpjpdKp\n" +
			"0xLTss8yBDHcZkgwvDrH8aTwUtq8gO67wY3JuWBxjTsnoAPbH8zInkHeolCUSobPxAx9XHqbAxfu\n" +
			"a8HJjDihi+cJYEb5lPSpvY5ytcPG9JAXAHQ6aalpJjkyB+eaGRYi8s5Ejr3luI3nzJEzfUj5y0fc\n" +
			"FTv9CtDt9VfblSuHdRw4uFwat5e1Fb7LtEjATi4cKaG1+zZ80QyuChfC08for83TeQgjq7TA10FA\n" +
			"kKe5nrXyHOORz+ttXkYkp5uEBhpZ</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:KeyDescriptor use=\"encryption\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIIDaDCCAlACCQDFsMECzdtetjANBgkqhkiG9w0BAQUFADB2MQswCQYDVQQGEwJVUzETMBEGA1UE\n" +
			"CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEfMB0GA1UECgwWUGl2b3RhbCBT\n" +
			"b2Z0d2FyZSwgSW5jLjEZMBcGA1UEAwwQKi5ydW4ucGl2b3RhbC5pbzAeFw0xNTA5MDIyMzIwMDla\n" +
			"Fw0xODA5MDEyMzIwMDlaMHYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYD\n" +
			"VQQHDA1TYW4gRnJhbmNpc2NvMR8wHQYDVQQKDBZQaXZvdGFsIFNvZnR3YXJlLCBJbmMuMRkwFwYD\n" +
			"VQQDDBAqLnJ1bi5waXZvdGFsLmlvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyz8C\n" +
			"OS7PJbmziNx1H2tpwSuDSX5ThqasDk/7LZ9FG8s/Zu8IqGQvswoGYx3CWgSaNbVA+Oj9zo7awoao\n" +
			"CLCVfU82O3RxH/gNRJQLwBVlgVys5n9UQ2xmTRMOcCTpR5d/zW4jCBgL4q2hjntgDbQNnQKJExgt\n" +
			"CGZJOQOFzsW3iG5NPfcAj+FPseVfD96I2OG3uxFPmO2Ov/EE7Hid6lETdNkXXEB2SxIebNgr03Dj\n" +
			"l6rFXTTdBXhi9gb+EQSZfbETsOHIDYIMLj0SpJvRcbA+7M4/Vynoxlv+/kICqFjjNATfOrqz7xoU\n" +
			"/VlMn1Z3op3cW8GH3iNHvGfIO7sdy2G0gQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQCq3PQDcIss\n" +
			"cIS1Dq++d1dD4vkGt+8IzYz+ijOLECyXsSm7+b4L+CVinFZ9eF99PLlvvJZ8+zA7NfM1wRpjpdKp\n" +
			"0xLTss8yBDHcZkgwvDrH8aTwUtq8gO67wY3JuWBxjTsnoAPbH8zInkHeolCUSobPxAx9XHqbAxfu\n" +
			"a8HJjDihi+cJYEb5lPSpvY5ytcPG9JAXAHQ6aalpJjkyB+eaGRYi8s5Ejr3luI3nzJEzfUj5y0fc\n" +
			"FTv9CtDt9VfblSuHdRw4uFwat5e1Fb7LtEjATi4cKaG1+zZ80QyuChfC08for83TeQgjq7TA10FA\n" +
			"kKe5nrXyHOORz+ttXkYkp5uEBhpZ</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://login.run.pivotal.io/saml/idp/SSO/alias/login.run.pivotal.io\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://login.run.pivotal.io/saml/idp/SSO/alias/login.run.pivotal.io\"/></md:IDPSSODescriptor></md:EntityDescriptor>";

	private static String METADATA_TRUST_CHECK_KEY =
		"MIIDaDCCAlACCQDFsMECzdtetjANBgkqhkiG9w0BAQUFADB2MQswCQYDVQQGEwJVUzETMBEGA1UE\n" +
			"CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEfMB0GA1UECgwWUGl2b3RhbCBT\n" +
			"b2Z0d2FyZSwgSW5jLjEZMBcGA1UEAwwQKi5ydW4ucGl2b3RhbC5pbzAeFw0xNTA5MDIyMzIwMDla\n" +
			"Fw0xODA5MDEyMzIwMDlaMHYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYD\n" +
			"VQQHDA1TYW4gRnJhbmNpc2NvMR8wHQYDVQQKDBZQaXZvdGFsIFNvZnR3YXJlLCBJbmMuMRkwFwYD\n" +
			"VQQDDBAqLnJ1bi5waXZvdGFsLmlvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyz8C\n" +
			"OS7PJbmziNx1H2tpwSuDSX5ThqasDk/7LZ9FG8s/Zu8IqGQvswoGYx3CWgSaNbVA+Oj9zo7awoao\n" +
			"CLCVfU82O3RxH/gNRJQLwBVlgVys5n9UQ2xmTRMOcCTpR5d/zW4jCBgL4q2hjntgDbQNnQKJExgt\n" +
			"CGZJOQOFzsW3iG5NPfcAj+FPseVfD96I2OG3uxFPmO2Ov/EE7Hid6lETdNkXXEB2SxIebNgr03Dj\n" +
			"l6rFXTTdBXhi9gb+EQSZfbETsOHIDYIMLj0SpJvRcbA+7M4/Vynoxlv+/kICqFjjNATfOrqz7xoU\n" +
			"/VlMn1Z3op3cW8GH3iNHvGfIO7sdy2G0gQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQCq3PQDcIss\n" +
			"cIS1Dq++d1dD4vkGt+8IzYz+ijOLECyXsSm7+b4L+CVinFZ9eF99PLlvvJZ8+zA7NfM1wRpjpdKp\n" +
			"0xLTss8yBDHcZkgwvDrH8aTwUtq8gO67wY3JuWBxjTsnoAPbH8zInkHeolCUSobPxAx9XHqbAxfu\n" +
			"a8HJjDihi+cJYEb5lPSpvY5ytcPG9JAXAHQ6aalpJjkyB+eaGRYi8s5Ejr3luI3nzJEzfUj5y0fc\n" +
			"FTv9CtDt9VfblSuHdRw4uFwat5e1Fb7LtEjATi4cKaG1+zZ80QyuChfC08for83TeQgjq7TA10FA\n" +
			"kKe5nrXyHOORz+ttXkYkp5uEBhpZ";
}
