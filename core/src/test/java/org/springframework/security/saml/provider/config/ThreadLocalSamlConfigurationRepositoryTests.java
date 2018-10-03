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

package org.springframework.security.saml.provider.config;

import java.time.Clock;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.stubbing.Answer;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ThreadLocalSamlConfigurationRepositoryTests {


	private ThreadLocalSamlConfigurationRepository repository;
	private SamlServerConfiguration configuration;
	private Clock clock;
	private InheritableThreadLocal threadLocal;
	MockHttpServletRequest request = new MockHttpServletRequest();

	@BeforeEach
	public void setup() {
		SamlConfigurationRepository mockConfig = mock(SamlConfigurationRepository.class);
		clock = mock(Clock.class);
		repository = new ThreadLocalSamlConfigurationRepository(mockConfig);
		configuration = new SamlServerConfiguration(null, null, null);
		when(mockConfig.getServerConfiguration(any())).thenReturn(configuration);
		when(clock.millis()).thenAnswer((Answer<Long>) invocation -> System.currentTimeMillis());
		threadLocal = (InheritableThreadLocal) ReflectionTestUtils
			.getField(ThreadLocalSamlConfigurationRepository.class, "threadLocal");
	}

	@AfterEach
	public void breakdown() {
		repository.setServerConfiguration(null);
	}

	@Test
	public void get_creates_clone() {
		assertNotSame(configuration, repository.getServerConfiguration(request));
	}

	@Test
	public void configuration_doesnt_get_set() {
		repository.getServerConfiguration(request);
		assertNull(threadLocal.get());
	}

	@Test
	public void cached_entry_is_returned() {
		SamlServerConfiguration c1 = repository.getServerConfiguration(request);
		repository.setServerConfiguration(c1);
		assertSame(c1, repository.getServerConfiguration(request));
	}

	@Test
	public void reset_works() {
		SamlServerConfiguration c1 = repository.getServerConfiguration(request);
		repository.setServerConfiguration(c1);
		assertNotNull(threadLocal.get());
		repository.reset();
		assertNull(threadLocal.get());
	}

	@Test
	public void set_null_works() {
		SamlServerConfiguration c1 = repository.getServerConfiguration(request);
		repository.setServerConfiguration(c1);
		assertNotNull(threadLocal.get());
		repository.setServerConfiguration(null);
		assertNull(threadLocal.get());
	}

}