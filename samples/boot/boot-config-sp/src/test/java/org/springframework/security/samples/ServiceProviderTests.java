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

import java.net.URI;
import java.time.Clock;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.boot.registration.RemoteIdentityProviderConfiguration;
import org.springframework.security.saml.boot.registration.SamlBootConfiguration;
import org.springframework.security.saml.helper.SamlTestObjectHelper;
import org.springframework.security.saml.registration.ExternalIdentityProviderConfiguration;
import org.springframework.security.saml.registration.HostedServiceProviderConfiguration;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.LogoutRequest;
import org.springframework.security.saml.saml2.authentication.LogoutResponse;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.authentication.StatusCode;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;
import org.springframework.security.saml.serviceprovider.ServiceProviderConfigurationResolver;
import org.springframework.security.saml.serviceprovider.spi.DefaultSamlAuthentication;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.security.saml.helper.SamlTestObjectHelper.queryParams;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
public class ServiceProviderTests {

	@Autowired
	MockMvc mockMvc;

	@Autowired
	SamlTransformer transformer;

	@Autowired
	SamlBootConfiguration bootConfiguration;

	@SpyBean
	ServiceProviderConfigurationResolver configuration;

	@BeforeEach
	void setUp() {
	}

	@AfterEach
	void reset() {
	}

	@SpringBootConfiguration
	@EnableAutoConfiguration
	@ComponentScan(basePackages = "sample")
	public static class SpringBootApplicationTestConfig {
	}

	@Test
	@DisplayName("Home Page is Secure and Redirects Automatically")
	void testHomePageSingleProvider() throws Exception {
		mockMvc.perform(
			get("/")

		)
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("http://localhost/saml/sp/select?redirect=true"))
		;

		mockMvc.perform(
			get("http://localhost/saml/sp/select?redirect=true")

		)
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl(
				"http://localhost/saml/sp/discovery?idp=http%3A%2F%2Fsimplesaml-for-spring-saml.cfapps.io%2Fsaml2%2Fidp%2Fmetadata.php"))
		;

		//no redirect without redirect parameter
		mockMvc.perform(
			get("http://localhost/saml/sp/select")

		)
			.andExpect(status().is2xxSuccessful())
		;
	}

	@Test
	@DisplayName("Home Page is Secure and Displays IDP Selection")
	void testHomePageMultipleProvider() throws Exception {
		List<RemoteIdentityProviderConfiguration> providers = bootConfiguration.getServiceProvider().getProviders();
		List<ExternalIdentityProviderConfiguration> list = new LinkedList<>();
		list.add(providers.get(0).toExternalIdentityProviderConfiguration());
		providers.get(0).setAlias(providers.get(0).getAlias() + "-2");
		providers.get(0).setLinktext("A Secondary SimpleSAML Provider");
		list.add(providers.get(0).toExternalIdentityProviderConfiguration());
		mockConfig(
			builder ->
				builder.providers(list)
		);
		mockMvc.perform(
			get("/")

		)
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("http://localhost/saml/sp/select?redirect=true"))
		;

		mockMvc.perform(
			get("http://localhost/saml/sp/select?redirect=true")

		)
			.andExpect(status().is2xxSuccessful())
			.andExpect(content().string(containsString(">Simple SAML PHP IDP<")))
			.andExpect(content().string(containsString(">A Secondary SimpleSAML Provider<")))
		;
	}

	@Test
	public void singleLogoutMetadata() throws Exception {
		mockConfig(builder -> builder.singleLogoutEnabled(true));
		ServiceProviderMetadata spm = getServiceProviderMetadata();
		assertThat(spm.getServiceProvider().getSingleLogoutService(), not(empty()));
	}

	@Test
	public void singleLogoutDisabledMetadata() throws Exception {
		mockConfig(builder -> builder.singleLogoutEnabled(false));
		ServiceProviderMetadata spm = getServiceProviderMetadata();
		assertThat(spm.getServiceProvider().getSingleLogoutService(), containsInAnyOrder());
	}


	@Test
	@DisplayName("SP Initiated Login")
	void getAuthNRequest() throws Exception {
		AuthenticationRequest authn = getAuthenticationRequest(
			"http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php");
		assertThat(
			authn.getDestination().getLocation(),
			equalTo("http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/SSOService.php")
		);
		assertThat(
			authn.getOriginEntityId(),
			equalTo("spring.security.saml.sp.id")
		);
		assertThat(
			authn.getSignature(),
			notNullValue()
		);

	}

	@Test
	@DisplayName("SP Initiated Login - Do not Sign requests")
	void getAuthNRequestNotSigned() throws Exception {
		mockConfig(builder -> builder.signRequests(false));
		AuthenticationRequest authn = getAuthenticationRequest(
			"http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php");
		assertThat(
			authn.getDestination().getLocation(),
			equalTo("http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/SSOService.php")
		);
		assertThat(
			authn.getOriginEntityId(),
			equalTo("spring.security.saml.sp.id")
		);
		assertThat(
			authn.getSignature(),
			nullValue()
		);
	}

	@Test
	void authenticate() throws Exception {
		ServiceProviderMetadata sp = getServiceProviderMetadata();
		IdentityProviderMetadata idp =
			(IdentityProviderMetadata) transformer.fromXml(
				bootConfiguration.getServiceProvider().getProviders().get(0).getMetadata(),
				null,
				null
			);
		SamlTestObjectHelper helper = new SamlTestObjectHelper(Clock.systemUTC());
		Assertion a = helper.assertion(
			sp,
			idp,
			null,
			"user@test.org",
			NameId.EMAIL
		);
		a.setSigningKey(
			SimpleSamlPhpTestKeys.getSimpleSamlPhpKeyData(),
			AlgorithmMethod.RSA_SHA256,
			DigestMethod.SHA256
		);
		Response r = helper.response(null, a, sp, idp);
		String xml = transformer.toXml(r);
		String encoded = transformer.samlEncode(xml, false);

		mockMvc.perform(
			post("/saml/sp/SSO")
				.param("SAMLResponse", encoded)
		).andExpect(authenticated());
	}

	@Test
	void authenticateWithOnlyResponseSigned() throws Exception {
		mockConfig(builder -> builder.wantAssertionsSigned(true));
		ServiceProviderMetadata sp = getServiceProviderMetadata();
		IdentityProviderMetadata idp =
			(IdentityProviderMetadata) transformer.fromXml(
				bootConfiguration.getServiceProvider().getProviders().get(0).getMetadata(),
				null,
				null
			);
		SamlTestObjectHelper helper = new SamlTestObjectHelper(Clock.systemUTC());
		Assertion a = helper.assertion(
			sp,
			idp,
			null,
			"user@test.org",
			NameId.EMAIL
		);
		Response r = helper.response(null, a, sp, idp);
		r.setSigningKey(
			SimpleSamlPhpTestKeys.getSimpleSamlPhpKeyData(),
			AlgorithmMethod.RSA_SHA256,
			DigestMethod.SHA256
		);
		String xml = transformer.toXml(r);
		String encoded = transformer.samlEncode(xml, false);

		mockMvc.perform(
			post("/saml/sp/SSO")
				.param("SAMLResponse", encoded)
		).andExpect(authenticated());
	}

	private AuthenticationRequest getAuthenticationRequest(String idpEntityId) throws Exception {
		MvcResult result = mockMvc.perform(
			get("/saml/sp/discovery")
				.param("idp", idpEntityId)
		)
			.andExpect(status().is3xxRedirection())
			.andReturn();

		String location = result.getResponse().getHeader("Location");
		Map<String, String> params = queryParams(new URI(location));
		String request = params.get("SAMLRequest");
		assertNotNull(request);
		String xml = transformer.samlDecode(request, true);
		Saml2Object saml2Object = transformer.fromXml(
			xml,
			bootConfiguration.getServiceProvider().getKeys().toList(),
			bootConfiguration.getServiceProvider().getKeys().toList()
		);
		assertNotNull(saml2Object);
		assertThat(saml2Object.getClass(), equalTo(AuthenticationRequest.class));
		return (AuthenticationRequest) saml2Object;
	}

	@Test
	@DisplayName("get Service Provider metadata")
	void testGetMetadata() throws Exception {
		ServiceProviderMetadata metadata = getServiceProviderMetadata();
		assertNotNull(metadata);
		assertThat(metadata.getEntityId(), equalTo("spring.security.saml.sp.id"));
	}

	@Test
	@DisplayName("Service Provider entity ID is generated")
	void generateSpEntityId() throws Exception {
		mockConfig(builder -> builder.entityId(null));
		ServiceProviderMetadata metadata = getServiceProviderMetadata();
		assertNotNull(metadata);
		assertThat(metadata.getEntityId(), equalTo("http://localhost"));
	}

	@Test
	@DisplayName("Service Provider entity ID is based on configured base path")
	void generateSpEntityIdFromBasePath() throws Exception {
		mockConfig(builder -> builder.entityId(null).basePath("http://some.other.host:8080/sample-sp"));
		ServiceProviderMetadata metadata = getServiceProviderMetadata();
		assertNotNull(metadata);
		assertThat(metadata.getEntityId(), equalTo("http://some.other.host:8080/sample-sp"));
		assertThat(metadata.getEntityAlias(), equalTo("some.other.host"));
	}

	@Test
	public void parseDualRemoteMetadata() throws Exception {
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
	public void invalidResponse() throws Exception {
		SamlTestObjectHelper helper = new SamlTestObjectHelper(Clock.systemUTC());
		ServiceProviderMetadata sp = getServiceProviderMetadata();
		IdentityProviderMetadata idp =
			(IdentityProviderMetadata) transformer.fromXml(
				bootConfiguration.getServiceProvider().getProviders().get(0).getMetadata(),
				null,
				null
			);
		Assertion assertion = helper.assertion(sp, idp, null, "test-user@test.com", NameId.PERSISTENT);
		Response response = helper.response(
			null,
			assertion,
			sp,
			idp
		);
		response.setDestination("invalid SP");

		String encoded = transformer.samlEncode(transformer.toXml(response), false);
		mockMvc.perform(
			post("/saml/sp/SSO/alias/boot-sample-sp")
				.param("SAMLResponse", encoded)
		)
			.andDo(print())
			.andExpect(status().isBadRequest())
			.andExpect(content().string(containsString("Destination mismatch: invalid SP")));
	}

	@Test
	public void initiateLogout() throws Exception {
		SamlTestObjectHelper helper = new SamlTestObjectHelper(Clock.systemUTC());
		ServiceProviderMetadata sp = getServiceProviderMetadata();
		IdentityProviderMetadata idp =
			(IdentityProviderMetadata) transformer.fromXml(
				bootConfiguration.getServiceProvider().getProviders().get(0).getMetadata(),
				null,
				null
			);
		Assertion assertion = helper.assertion(sp, idp, null, "test-user@test.com", NameId.PERSISTENT);
		DefaultSamlAuthentication authentication = new DefaultSamlAuthentication(
			true,
			assertion,
			idp.getEntityId(),
			sp.getEntityId(),
			null
		);

		String location = sp.getServiceProvider().getSingleLogoutService().get(0).getLocation();
		location = location.substring(location.indexOf("/saml/sp"));
		String redirect = mockMvc.perform(
			get(location)
				.with(authentication(authentication))
		)
			.andExpect(status().isFound())
			.andReturn()
			.getResponse()
			.getHeader("Location");

		Map<String, String> params = queryParams(new URI(redirect));
		String request = params.get("SAMLRequest");
		assertNotNull(request);
		LogoutRequest lr = (LogoutRequest) transformer.fromXml(
			transformer.samlDecode(request, true),
			null,
			null
		);
		assertNotNull(lr);
	}

	@Test
	public void receiveLogoutRequest() throws Exception {
		SamlTestObjectHelper helper = new SamlTestObjectHelper(Clock.systemUTC());
		ServiceProviderMetadata sp = getServiceProviderMetadata();
		IdentityProviderMetadata idp =
			(IdentityProviderMetadata) transformer.fromXml(
				bootConfiguration.getServiceProvider().getProviders().get(0).getMetadata(),
				null,
				null
			);
		Assertion assertion = helper.assertion(sp, idp, null, "test-user@test.com", NameId.PERSISTENT);
		DefaultSamlAuthentication authentication = new DefaultSamlAuthentication(
			true,
			assertion,
			idp.getEntityId(),
			sp.getEntityId(),
			null
		);
		LogoutRequest request = helper.logoutRequest(
			sp,
			idp,
			assertion.getSubject().getPrincipal()
		);

		String xml = transformer.toXml(request);
		String param = transformer.samlEncode(xml, true);

		String location = sp.getServiceProvider().getSingleLogoutService().get(0).getLocation();
		location = location.substring(location.indexOf("/saml/sp"));
		String redirect = mockMvc.perform(
			get(location)
				.param("SAMLRequest", param)
				.with(authentication(authentication))
		)
			.andExpect(status().isFound())
			.andExpect(unauthenticated())
			.andReturn()
			.getResponse()
			.getHeader("Location");

		Map<String, String> params = queryParams(new URI(redirect));
		String response = params.get("SAMLResponse");
		assertNotNull(response);
		LogoutResponse lr = (LogoutResponse) transformer.fromXml(
			transformer.samlDecode(response, true),
			null,
			null
		);
		assertNotNull(lr);
		assertThat(lr.getStatus().getCode(), equalTo(StatusCode.SUCCESS));

	}

	@Test
	public void receiveLogoutResponse() throws Exception {
		SamlTestObjectHelper helper = new SamlTestObjectHelper(Clock.systemUTC());
		ServiceProviderMetadata sp = getServiceProviderMetadata();
		IdentityProviderMetadata idp =
			(IdentityProviderMetadata) transformer.fromXml(
				bootConfiguration.getServiceProvider().getProviders().get(0).getMetadata(),
				null,
				null
			);
		Assertion assertion = helper.assertion(sp, idp, null, "test-user@test.com", NameId.PERSISTENT);
		DefaultSamlAuthentication authentication = new DefaultSamlAuthentication(
			true,
			assertion,
			idp.getEntityId(),
			sp.getEntityId(),
			null
		);
		LogoutRequest request = helper.logoutRequest(
			idp,
			sp,
			assertion.getSubject().getPrincipal()
		);

		LogoutResponse response = helper.logoutResponse(request, sp, idp);

		String xml = transformer.toXml(response);
		String param = transformer.samlEncode(xml, true);

		String location = sp.getServiceProvider().getSingleLogoutService().get(0).getLocation();
		location = location.substring(location.indexOf("/saml/sp"));
		mockMvc.perform(
			get(location)
				.param("SAMLResponse", param)
				.with(authentication(authentication))
		)
			.andExpect(status().isFound())
			.andExpect(unauthenticated())
			.andExpect(redirectedUrl("/saml/sp/select"))
		;
	}

	@Test
	void notLoggedInLoggingOut() throws Exception {
		mockMvc.perform(
			get("/saml/sp/logout")
		)
			.andExpect(status().isFound())
			.andExpect(unauthenticated())
			.andExpect(redirectedUrl("/saml/sp/select"))
		;
	}

	@Test
	void nonSamlSessionLoggingOut() throws Exception {
		mockMvc.perform(
			get("/saml/sp/logout")
			.with(
				authentication(
					new UsernamePasswordAuthenticationToken("user", null, Collections.emptyList())
				)
			)
		)
			.andExpect(status().isFound())
			.andExpect(unauthenticated())
			.andExpect(redirectedUrl("/saml/sp/select"))
		;
	}


	private void mockConfig(Consumer<HostedServiceProviderConfiguration.Builder> modifier) {
		Mockito.doAnswer(
			invocation -> {
				HostedServiceProviderConfiguration config =
					(HostedServiceProviderConfiguration) invocation.callRealMethod();
				HostedServiceProviderConfiguration.Builder builder =
					HostedServiceProviderConfiguration.builder(config);
				modifier.accept(builder);
				return builder.build();
			}
		)
			.when(configuration).resolve(ArgumentMatchers.any(HttpServletRequest.class));
	}

	private ServiceProviderMetadata getServiceProviderMetadata() throws Exception {
		String xml = mockMvc.perform(get("/saml/sp/metadata"))
			.andExpect(status().isOk())
			.andReturn()
			.getResponse()
			.getContentAsString();
		assertNotNull(xml);
		Metadata m = (Metadata) transformer.fromXml(xml, null, null);
		assertNotNull(m);
		assertThat(m.getClass(), equalTo(ServiceProviderMetadata.class));
		return (ServiceProviderMetadata) m;
	}

	private static final String IDP_DUAL_METADATA =
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
}
