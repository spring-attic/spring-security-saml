/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.springframework.security.saml.spi;

import java.time.Clock;

import org.springframework.security.saml.SamlProviderNotFoundException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestOperations;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static java.util.Arrays.asList;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

class DefaultMetadataCacheTests {

	private Clock clock = mock(Clock.class);
	private RestOperations validatingNetwork = mock(RestOperations.class);
	private RestOperations nonValidatingNetwork = mock(RestOperations.class);

	private DefaultMetadataCache cache;

	private String hitUrl = "hit.url.com";
	private String missUrl = "miss.url.com";
	private Class<byte[]> byteClass = byte[].class;

	private long cacheTime = 1000;
	private long missTime = 1000;

	@BeforeEach
	void setUp() {
		cache = new DefaultMetadataCache(clock, validatingNetwork, nonValidatingNetwork)
			.setCacheHitDurationMillis(cacheTime)
			.setCacheMissDurationMillis(missTime);

		for (RestOperations network : asList(validatingNetwork, nonValidatingNetwork)) {
			when(network.getForObject(hitUrl, byteClass)).thenAnswer(invocation -> new byte[0]); //new object each time
			when(network.getForObject(missUrl, byteClass)).thenThrow(new ResourceAccessException(missUrl));
		}
		when(clock.millis()).thenAnswer(invocation -> System.currentTimeMillis());
	}

	@AfterEach
	void tearDown() {
	}


	@Test
	void nonValidatingNetworkCalled() {
		cache.getMetadata(hitUrl, false);
		verify(validatingNetwork).getForObject(hitUrl, byteClass);
		verifyZeroInteractions(nonValidatingNetwork);
	}

	@Test
	void validatingNetworkCalled() {
		cache.getMetadata(hitUrl, true);
		verify(nonValidatingNetwork).getForObject(hitUrl, byteClass);
		verifyZeroInteractions(validatingNetwork);
	}

	@Test
	void correctExceptionWhenMiss() {
		Assertions.assertThrows(
			SamlProviderNotFoundException.class,
			() -> cache.getMetadata(missUrl, true)
		);
	}

	@Test
	void cacheWorks() {
		Object hit1 = cache.getMetadata(hitUrl, true);
		Object hit2 = cache.getMetadata(hitUrl, true);
		assertSame(hit1, hit2);
	}

	@Test
	void cacheExpires() {
		Object hit1 = cache.getMetadata(hitUrl, true);
		reset(clock);
		when(clock.millis()).thenReturn(System.currentTimeMillis() + (2 * cacheTime));
		Object hit2 = cache.getMetadata(hitUrl, true);
		assertNotSame(hit1, hit2);
	}

	@Test
	void cacheMissWorks() {
		SamlProviderNotFoundException miss1 = doMiss();
		SamlProviderNotFoundException miss2 = doMiss();
		assertSame(miss1, miss2);
	}


	@Test
	void cacheMissExpires() {
		SamlProviderNotFoundException miss1 = doMiss();
		reset(clock);
		when(clock.millis()).thenReturn(System.currentTimeMillis() + (2 * missTime));
		SamlProviderNotFoundException miss2 = doMiss();
		assertNotSame(miss1, miss2);
	}

	private SamlProviderNotFoundException doMiss() {
		try {
			cache.getMetadata(missUrl, true);
		} catch (SamlProviderNotFoundException e) {
			return e;
		}
		throw new IllegalStateException();
	}

}