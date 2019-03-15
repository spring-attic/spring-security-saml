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
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.xml.datatype.Duration;

import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.signature.Signature;

/**
 * Static utility class that serves as the delimiter between Spring Security SAML and underlying implementation.
 *
 * @param <T> generic type for subclass in order to have a working builder pattern for subclasses
 */
public abstract class SpringSecuritySaml<T extends SpringSecuritySaml> {

	private final AtomicBoolean hasInitCompleted = new AtomicBoolean(false);
	private Clock time;

	public SpringSecuritySaml(Clock time) {
		this.time = time;
	}

	public Clock getTime() {
		return time;
	}


	@SuppressWarnings("checked")
	public T init() {
		if (!hasInitCompleted.get()) {
			performInit();
		}
		return (T) this;
	}

	protected synchronized void performInit() {
		if (hasInitCompleted.compareAndSet(false, true)) {
			java.security.Security.addProvider(
				new org.bouncycastle.jce.provider.BouncyCastleProvider()
			);
			bootstrap();
		}
	}

	protected abstract void bootstrap();

	public abstract long toMillis(Duration duration);

	public abstract Duration toDuration(long millis);

	public abstract String toXml(Saml2Object saml2Object);

	public abstract Saml2Object resolve(
		String xml, List<SimpleKey> verificationKeys, List<SimpleKey>
		localKeys
	);

	public abstract Saml2Object resolve(byte[] xml, List<SimpleKey> trustedKeys, List<SimpleKey> localKeys);

	public abstract Signature validateSignature(Saml2Object saml2Object, List<SimpleKey> trustedKeys);

	public String encode(byte[] b) {
		return EncodingUtils.encode(b);
	}

	public byte[] decode(String s) {
		return EncodingUtils.decode(s);
	}

	public byte[] deflate(String s) {
		return EncodingUtils.deflate(s);
	}

	public String inflate(byte[] b) {
		return EncodingUtils.inflate(b);
	}


}
