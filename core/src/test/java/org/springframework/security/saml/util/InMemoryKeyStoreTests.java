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

package org.springframework.security.saml.util;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.saml.init.SpringSecuritySaml;

import static org.springframework.security.saml.spi.ExamplePemKey.IDP_RSA_KEY;
import static org.springframework.security.saml.spi.ExamplePemKey.RSA_TEST_KEY;
import static org.springframework.security.saml.spi.ExamplePemKey.SP_RSA_KEY;

class InMemoryKeyStoreTests {

    @BeforeAll
    public static void init() {
        SpringSecuritySaml.getInstance().init();
    }

    @Test
    public void test_example() {
        InMemoryKeyStore.fromKey(RSA_TEST_KEY.getSimpleKey("alias"));
    }

    @Test
    public void test_idp_1024() {
        InMemoryKeyStore.fromKey(IDP_RSA_KEY.getSimpleKey("alias"));
    }

    @Test
    public void test_sp_1024() {
        InMemoryKeyStore.fromKey(SP_RSA_KEY.getSimpleKey("alias"));
    }
}