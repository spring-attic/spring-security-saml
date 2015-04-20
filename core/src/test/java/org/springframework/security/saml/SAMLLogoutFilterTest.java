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
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

/**
 * @author Rob Winch
 */
public class SAMLLogoutFilterTest {
    SAMLLogoutFilter filter;

    MockHttpServletRequest request;
    MockHttpServletResponse response;

    private LogoutHandler[] handlers;

    @Before
    public void setup() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        handlers = new LogoutHandler[] { new SecurityContextLogoutHandler() };
        filter = new SAMLLogoutFilter("/logout", handlers, handlers);
    }

    @Test
    public void requiresLogout() {
        assertEquals(false, filter.requiresLogout(request, response));

        request.setRequestURI("/logout");

        assertEquals(false, filter.requiresLogout(request, response));
    }

    @Test
    public void constructorStringLogoutHandlersLogoutHandlersNotNullFilterProcessUrl() {
        assertNotNull(filter.getFilterProcessesUrl());
    }

    @Test
    public void constructorLogoutSuccessHandlerLogoutHandlersLogoutHandlersNotNullFilterProcessUrl() {
        filter = new SAMLLogoutFilter(new SimpleUrlLogoutSuccessHandler(), handlers, handlers);
        assertNotNull(filter.getFilterProcessesUrl());
    }
}
