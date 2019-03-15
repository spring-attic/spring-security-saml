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

package org.springframework.security.saml.provider.config;

public class NetworkConfiguration implements Cloneable {
	private int readTimeout;
	private int connectTimeout;

	public int getReadTimeout() {
		return readTimeout;
	}

	public NetworkConfiguration setReadTimeout(int readTimeout) {
		this.readTimeout = readTimeout;
		return this;
	}

	public int getConnectTimeout() {
		return connectTimeout;
	}

	public NetworkConfiguration setConnectTimeout(int connectTimeout) {
		this.connectTimeout = connectTimeout;
		return this;
	}

	@Override
	public NetworkConfiguration clone() throws CloneNotSupportedException {
		return (NetworkConfiguration) super.clone();
	}
}
