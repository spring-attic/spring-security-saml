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
package org.springframework.security.samples;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.MediaType;
import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.provider.service.config.ExternalIdentityProviderConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
public class SelectIdentityProviderBootTest {

	@Autowired
	private MockMvc mockMvc;

	private String idpEntityId;

	private String spBaseUrl;

	@Autowired
	@Qualifier("spSamlServerConfiguration")
	private SamlServerConfiguration config;

	private List<ExternalIdentityProviderConfiguration> providers;

	@BeforeEach
	void setUp() {
		idpEntityId = "http://dual.sp-idp.com/saml/idp/metadata";
		providers = config.getServiceProvider().getProviders();
		List<ExternalIdentityProviderConfiguration> newConfig = new ArrayList<>(providers);
		newConfig.add(
			new ExternalIdentityProviderConfiguration()
				.setAlias("dual")
				.setMetadata(IDP_DUAL_METADATA)
				.setSkipSslValidation(true)
				.setLinktext("Dual IDP/SP Metadata")
		);
		config.getServiceProvider().setProviders(newConfig);

		spBaseUrl = "http://localhost";
		config.getServiceProvider().setBasePath(spBaseUrl);
	}

	@AfterEach
	public void reset() {
		config.getServiceProvider().setSingleLogoutEnabled(true);
		config.getServiceProvider().setProviders(providers);
	}

	@Test
	public void selectIdentityProvider() throws Exception {
		mockMvc.perform(
			get("/saml/sp/select")
				.accept(MediaType.TEXT_HTML)
		)
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("<h1>Select an Identity Provider</h1>")))
			.andExpect(content().string(containsString("Dual IDP/SP Metadata")))
			.andReturn();
	}

	private static final String IDP_DUAL_METADATA = "<ns3:EntityDescriptor xmlns:ns3=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns=\"http://www.w3.org/2000/09/xmldsig#\"\n" +
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
}
