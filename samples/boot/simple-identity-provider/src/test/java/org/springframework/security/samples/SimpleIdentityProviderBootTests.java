/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
*/

package org.springframework.security.samples;

import java.util.Collections;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.saml.SamlObjectResolver;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.spi.DefaultMetadataCache;
import org.springframework.security.saml.spi.Defaults;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import sample.config.AppConfig;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
public class SimpleIdentityProviderBootTests {
	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private SamlTransformer transformer;

	@Autowired
	private Defaults defaults;

	@Autowired
	private SamlObjectResolver resolver;

	@MockBean
	private DefaultMetadataCache cache;

	@Autowired
	private AppConfig config;

	@BeforeEach
	public void mockCache() {
		given(cache.getMetadata(anyString(), anyBoolean())).willReturn(CACHED_META_DATA.getBytes());
	}

	@AfterEach
	public void reset() {
		config.getIdentityProvider().setSingleLogoutEnabled(true);
	}

	@SpringBootConfiguration
	@EnableAutoConfiguration
	@ComponentScan(basePackages = "sample")
	public static class SpringBootApplicationTestConfig {
	}

	@Test
	public void testIdentityProviderMetadata() throws Exception {
		IdentityProviderMetadata idpm = getIdentityProviderMetadata();
		assertThat(idpm.getIdentityProvider().getSingleLogoutService().isEmpty(), equalTo(false));
		assertThat(idpm.getEntityAlias(), equalTo("spring.security.saml.idp.id"));
		for (Endpoint ep : idpm.getIdentityProvider().getSingleSignOnService()) {
			assertThat(ep.getLocation(), equalTo("http://localhost:80/saml/idp/SSO/alias/boot-sample-idp"));
		}

	}

	@Test
	public void singleLogoutDisabledMetadata() throws Exception {
		config.getIdentityProvider().setSingleLogoutEnabled(false);
		IdentityProviderMetadata idpm = getIdentityProviderMetadata();
		assertThat(idpm.getIdentityProvider().getSingleLogoutService(), containsInAnyOrder());
	}

	@Test
	public void idpInitiatedLogin() throws Exception {
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user", null, Collections.emptyList());
		MvcResult result = mockMvc.perform(
			get("/saml/idp/init")
				.param("sp", "spring.security.saml.sp.id")
				.with(authentication(token))
		)
			.andExpect(status().isOk())
			.andReturn();
		String html = result.getResponse().getContentAsString();
		assertThat(html, containsString("name=\"SAMLResponse\""));
		String response = extractResponse(html, "SAMLResponse");
		Response r = (Response) transformer.fromXml(transformer.samlDecode(response, false), null, null);
		assertNotNull(r);
		assertThat(r.getAssertions(), notNullValue());
		assertThat(r.getAssertions().size(), equalTo(1));
	}

	@Test
	public void receiveAuthenticationRequest() throws Exception {
		IdentityProviderMetadata local = resolver.getLocalIdentityProvider("http://localhost");
		ServiceProviderMetadata sp = resolver.resolveServiceProvider("spring.security.saml.sp.id");
		assertNotNull(sp);

		AuthenticationRequest authenticationRequest = defaults.authenticationRequest(sp, local);
		String xml = transformer.toXml(authenticationRequest);
		String deflated = transformer.samlEncode(xml, true);

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user", null, Collections.emptyList());
		MvcResult result = mockMvc.perform(
			get("/saml/idp/SSO/alias/boot-sample-idp")
				.param("SAMLRequest", deflated)
				.with(authentication(token))
		)
			.andExpect(status().isOk())
			.andReturn();
		String html = result.getResponse().getContentAsString();
		assertThat(html, containsString("name=\"SAMLResponse\""));
		String response = extractResponse(html, "SAMLResponse");
		Response r = (Response) transformer.fromXml(transformer.samlDecode(response, false), null, null);
		assertNotNull(r);
		assertThat(r.getAssertions(), notNullValue());
		assertThat(r.getAssertions().size(), equalTo(1));

	}

	protected IdentityProviderMetadata getIdentityProviderMetadata() throws Exception {
		MvcResult result = mockMvc.perform(get("/saml/idp/metadata"))
			.andExpect(status().isOk())
			.andReturn();
		String xml = result.getResponse().getContentAsString();
		Metadata m = (Metadata) transformer.fromXml(xml, null, null);
		assertNotNull(m);
		assertThat(m.getClass(), equalTo(IdentityProviderMetadata.class));
		return (IdentityProviderMetadata)m;
	}

	private String extractResponse(String html, String name) {
		Pattern p = Pattern.compile(" name=\"(.*?)\" value=\"(.*?)\"");
		Matcher m = p.matcher(html);
		while (m.find()) {
			String pname = m.group(1);
			String value = m.group(2);
			if (name.equals(pname)) {
				return value;
			}
		}
		return null;
	}

	public static final String CACHED_META_DATA = "\n" +
		"<md:EntityDescriptor ID=\"dfc08e8f-ab6e-4682-aa34-6e7fcd812892\" entityID=\"spring.security.saml.sp.id\" xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\"><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
		"<ds:SignedInfo>\n" +
		"<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
		"<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n" +
		"<ds:Reference URI=\"#dfc08e8f-ab6e-4682-aa34-6e7fcd812892\">\n" +
		"<ds:Transforms>\n" +
		"<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n" +
		"<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
		"</ds:Transforms>\n" +
		"<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n" +
		"<ds:DigestValue>SMvLzAh6oFKgdeC0bfQrzM6fZbk=</ds:DigestValue>\n" +
		"</ds:Reference>\n" +
		"</ds:SignedInfo>\n" +
		"<ds:SignatureValue>\n" +
		"P6bbFySzan13eW77u8qs3DdYJWl65zFK0vbPLHbPWcsl2m9JwI++4iQP5QSwrde9AlHRDqOK6wUv\n" +
		"UauUWqSG4mIiPb0/r9l12+stSGrjtkLU44Md+04UK1/fWOiGXKkpDVlrKirvw3RCYOtIcvGv2rqd\n" +
		"nBMyf6B6PiBW1RhSlp0=\n" +
		"</ds:SignatureValue>\n" +
		"<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMCVVMxEzARBgNV\n" +
		"BAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsGA1UECgwUU3ByaW5nIFNlY3Vy\n" +
		"aXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQDDBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAe\n" +
		"Fw0xODA1MTQxNDMwNDRaFw0yODA1MTExNDMwNDRaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwK\n" +
		"V2FzaGluZ3RvbjESMBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkg\n" +
		"U0FNTDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1sMIGfMA0G\n" +
		"CSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRu7/EI0BlNzMEBFVAcbx+lLosvzIWU+01dGTY8gBdhMQN\n" +
		"YKZ92lMceo2CuVJ66cUURPym3i7nGGzoSnAxAre+0YIM+U0razrWtAUE735bkcqELZkOTZLelaoO\n" +
		"ztmWqRbe5OuEmpewH7cx+kNgcVjdctOGy3Q6x+I4qakY/9qhBQIDAQABMA0GCSqGSIb3DQEBCwUA\n" +
		"A4GBAAeViTvHOyQopWEiXOfI2Z9eukwrSknDwq/zscR0YxwwqDBMt/QdAODfSwAfnciiYLkmEjlo\n" +
		"zWRtOeN+qK7UFgP1bRl5qksrYX5S0z2iGJh0GvonLUt3e20Ssfl5tTEDDnAEUMLfBkyaxEHDRZ/n\n" +
		"bTJ7VTeZOSyRoVn5XHhpuJ0B</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><md:SPSSODescriptor AuthnRequestsSigned=\"true\" ID=\"cabd4887-532f-4259-822f-960c55de6249\" WantAssertionsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:Extensions/><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMCVVMxEzARBgNV\n" +
		"BAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsGA1UECgwUU3ByaW5nIFNlY3Vy\n" +
		"aXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQDDBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAe\n" +
		"Fw0xODA1MTQxNDMwNDRaFw0yODA1MTExNDMwNDRaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwK\n" +
		"V2FzaGluZ3RvbjESMBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkg\n" +
		"U0FNTDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1sMIGfMA0G\n" +
		"CSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRu7/EI0BlNzMEBFVAcbx+lLosvzIWU+01dGTY8gBdhMQN\n" +
		"YKZ92lMceo2CuVJ66cUURPym3i7nGGzoSnAxAre+0YIM+U0razrWtAUE735bkcqELZkOTZLelaoO\n" +
		"ztmWqRbe5OuEmpewH7cx+kNgcVjdctOGy3Q6x+I4qakY/9qhBQIDAQABMA0GCSqGSIb3DQEBCwUA\n" +
		"A4GBAAeViTvHOyQopWEiXOfI2Z9eukwrSknDwq/zscR0YxwwqDBMt/QdAODfSwAfnciiYLkmEjlo\n" +
		"zWRtOeN+qK7UFgP1bRl5qksrYX5S0z2iGJh0GvonLUt3e20Ssfl5tTEDDnAEUMLfBkyaxEHDRZ/n\n" +
		"bTJ7VTeZOSyRoVn5XHhpuJ0B</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIICgTCCAeoCCQCQqf5mvKPOpzANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMCVVMxEzARBgNV\n" +
		"BAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsGA1UECgwUU3ByaW5nIFNlY3Vy\n" +
		"aXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQDDBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAe\n" +
		"Fw0xODA1MTQxNDQ0NDZaFw0yODA1MTExNDQ0NDZaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwK\n" +
		"V2FzaGluZ3RvbjESMBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkg\n" +
		"U0FNTDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1sMIGfMA0G\n" +
		"CSqGSIb3DQEBAQUAA4GNADCBiQKBgQCXJXpaDE6QmY9eN9pwcG8k/54aK9YLzRgln64hZ6mvdK+O\n" +
		"IIBB5E2Pgenfc3Pi8pF0B9dGUbbNK8+8L6HcZRT/3aXMWlJsENJdMS13pnmSFimsTqoxYnayc2Ea\n" +
		"HULtvhMvLKf7UPRwX4jzxLanc6R4IcULJZ/dg9gBT5KDlm164wIDAQABMA0GCSqGSIb3DQEBCwUA\n" +
		"A4GBAHDyh2B4AZ1C9LSigis+sAiVJIzODsnKg8pIWGI7bcFUK+i/Vj7qlx09ZD/GbrQts87Yp4aq\n" +
		"+5OqVqb5n6bS8DWB8jHCoHC5HACSBb3J7x/mC0PBsKXA9A8NSFzScErvfD/ACjWg3DJEghxnlqAV\n" +
		"Tm/DQX/t8kNTdrLdlzsYTuE0</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIICgTCCAeoCCQC3dvhia5XvzjANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMCVVMxEzARBgNV\n" +
		"BAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsGA1UECgwUU3ByaW5nIFNlY3Vy\n" +
		"aXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQDDBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAe\n" +
		"Fw0xODA1MTQxNDQ1MzBaFw0yODA1MTExNDQ1MzBaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwK\n" +
		"V2FzaGluZ3RvbjESMBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkg\n" +
		"U0FNTDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1sMIGfMA0G\n" +
		"CSqGSIb3DQEBAQUAA4GNADCBiQKBgQC2iAUrJXrHaSOWrU95v8GUGVVl5vWrYrNRFtsK5qkhB/nR\n" +
		"bL08CbqIeD4pkJuIg0LuJdsBuMtYqOnhQSFF5tT36OIdld9SfPA5m8zqPLsCcjWPQ66xoMdReEXN\n" +
		"9E8s/mZOXn3jkKIqywUxJ+wkS5qoBlvmShwDff+igFlF/fBfpwIDAQABMA0GCSqGSIb3DQEBCwUA\n" +
		"A4GBACDBjvIpc1/2yZ3TQe29bKif5pr/3NdKz4MWBJ6vjRk7Bs2hbPrM2ajxLbqPx6PRPeTOw5XZ\n" +
		"grufDj9HmrvKHM2LZTp/cIUpxcNpVRyDA4iVNDc7V3qszaWP9ZIswAYnvmyDL2UHVDLE8xoGz/Ak\n" +
		"xsRNN9VXNHewjQO605umiAKJ</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost:8080/sample-sp/saml/sp/logout\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8080/sample-sp/saml/sp/SSO\" index=\"0\" isDefault=\"true\"/><md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost:8080/sample-sp/saml/sp/SSO\" index=\"1\" isDefault=\"false\"/><md:AttributeConsumingService index=\"0\" isDefault=\"true\"/></md:SPSSODescriptor></md:EntityDescriptor>";

}
