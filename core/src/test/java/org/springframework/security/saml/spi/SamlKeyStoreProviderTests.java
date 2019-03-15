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
package org.springframework.security.saml.spi;

import java.time.Clock;

import org.springframework.security.saml.spi.opensaml.OpenSamlImplementation;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.springframework.security.saml.spi.ExamplePemKey.IDP_RSA_KEY;
import static org.springframework.security.saml.spi.ExamplePemKey.RSA_TEST_KEY;
import static org.springframework.security.saml.spi.ExamplePemKey.SP_RSA_KEY;

public class SamlKeyStoreProviderTests {

	@BeforeAll
	public static void initProvider() {
		new OpenSamlImplementation(Clock.systemUTC()).init();
	}
	@Test
	public void test_example() {
		new SamlKeyStoreProvider(){}.getKeyStore(RSA_TEST_KEY.getSimpleKey("alias"));
	}

	@Test
	public void test_idp_1024() {
		new SamlKeyStoreProvider(){}.getKeyStore(IDP_RSA_KEY.getSimpleKey("alias"));
	}

	@Test
	public void test_sp_1024() {
		new SamlKeyStoreProvider(){}.getKeyStore(SP_RSA_KEY.getSimpleKey("alias"));
	}
}