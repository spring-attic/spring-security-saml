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
package org.springframework.security.saml.saved_for_later;

import java.time.Clock;

import org.springframework.web.client.RestOperations;

import static java.lang.String.format;

/**
 * Caches metadata that has been retrieved over the network
 *
 * @author fhanik
 */
public class DefaultMetadataCache implements SamlMetadataCache {

	private final RestOperations validatingNetwork;
	private final RestOperations nonValidatingNetwork;

	private TimebasedMap<String, byte[]> cache;

	public DefaultMetadataCache(Clock time,
								RestOperations validatingNetwork,
								RestOperations nonValidatingNetwork) {
		cache = new TimebasedMap<>(time);
		this.validatingNetwork = validatingNetwork;
		this.nonValidatingNetwork = nonValidatingNetwork;
	}

	public byte[] getMetadata(String uri, boolean skipSslValidation) {
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
				throw new SamlMetadataException(
					format("Unable to download SAML metadata[%s]", uri),
					x
				);
			}
		}
		return data;
	}

	public void clear() {
		cache.clear();
	}

	@Override
	public byte[] remove(String uri) {
		return cache.remove(uri);
	}
}
