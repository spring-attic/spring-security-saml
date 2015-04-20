/*
 * Copyright 2002-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.saml;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

/**
 * @author Rob Winch
 */
public class SAMLLogoutProcessingFilterTest {
    SAMLLogoutProcessingFilter filter;

    LogoutHandler[] logoutHandlers;

    @Before
    public void setup() {
        logoutHandlers = new LogoutHandler[] { new SecurityContextLogoutHandler() };
    }

    @Test
    public void constructorStringLogoutHanldersNotNullFilterProcessUrl() {
        filter = new SAMLLogoutProcessingFilter("/", logoutHandlers);

        assertNotNull(filter.getFilterProcessesUrl());
    }

    @Test
    public void constructorLogoutSuccessHandlerLogoutHanldersNotNullFilterProcessUrl() {
        filter = new SAMLLogoutProcessingFilter(new SimpleUrlLogoutSuccessHandler(), logoutHandlers);

        assertNotNull(filter.getFilterProcessesUrl());
    }
}
