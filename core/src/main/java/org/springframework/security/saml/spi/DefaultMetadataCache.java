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

import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.SamlProviderNotFoundException;
import org.springframework.web.client.RestOperations;

import static java.lang.String.format;
import static java.util.Objects.nonNull;

/**
 * Caches metadata that has been retrieved over the network
 *
 * @author fhanik
 */
public class DefaultMetadataCache implements SamlMetadataCache {

	private final RestOperations validatingNetwork;
	private final RestOperations nonValidatingNetwork;

	private TimebasedMap<String, byte[]> cache;
	private TimebasedMap<String, SamlProviderNotFoundException> misses;

	public DefaultMetadataCache(Clock time,
								RestOperations validatingNetwork,
								RestOperations nonValidatingNetwork) {
		cache = new TimebasedMap<>(time);
		cache.setFrequencyIntervalMills(1000 * 60 * 2);
		cache.setExpirationTimeMills(1000 * 60 * 10); //10 minutes default for hits
		misses = new TimebasedMap<>(time);
		misses.setFrequencyIntervalMills(1000 * 60 * 2);
		misses.setExpirationTimeMills(1000 * 60 * 5); //5 minutes default for misses
		this.validatingNetwork = validatingNetwork;
		this.nonValidatingNetwork = nonValidatingNetwork;
	}

	public long getCacheHitDurationMillis() {
		return cache.getExpirationTimeMills();
	}

	public DefaultMetadataCache setCacheHitDurationMillis(long cacheHitDurationMillis) {
		cache.setExpirationTimeMills(cacheHitDurationMillis);
		cache.setFrequencyIntervalMills(Math.round((double)cacheHitDurationMillis / 2.0d));
		return this;
	}

	public long getCacheMissDurationMillis() {
		return misses.getExpirationTimeMills();
	}

	public DefaultMetadataCache setCacheMissDurationMillis(long cacheMissDurationMillis) {
		misses.setExpirationTimeMills(cacheMissDurationMillis);
		misses.setFrequencyIntervalMills(Math.round((double)cacheMissDurationMillis / 2.0d));
		return this;
	}

	public byte[] getMetadata(String uri, boolean skipSslValidation) {
		final SamlProviderNotFoundException hasMiss = misses.get(uri);
		if (nonNull(hasMiss)) {
			throw hasMiss;
		}
		byte[] data = cache.get(uri);
		if (data == null) {
			try {
				if (skipSslValidation) {
					data = nonValidatingNetwork.getForObject(uri, byte[].class);
				}
				else {
					data = validatingNetwork.getForObject(uri, byte[].class);
				}
				cache.put(uri, data);
			} catch (Exception x) {
				SamlProviderNotFoundException ex = new SamlProviderNotFoundException(
					format("Unable to download SAML metadata[%s]", uri),
					x
				);
				misses.put(uri, ex);
				throw ex;
			}
		}
		return data;
	}

	public void clear() {
		misses.clear();
		cache.clear();
	}

	@Override
	public byte[] remove(String uri) {
		misses.remove(uri);
		return cache.remove(uri);
	}
}