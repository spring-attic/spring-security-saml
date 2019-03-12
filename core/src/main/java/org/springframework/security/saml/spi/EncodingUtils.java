/*
 * Copyright 2002-2019 the original author or authors.
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;

import org.springframework.security.saml.SamlException;

import org.apache.commons.codec.binary.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.zip.Deflater.DEFLATED;

class EncodingUtils {
	private static Base64 UNCHUNKED_ENCODER = new Base64(0, new byte[]{'\n'});

	public static String encode(byte[] b) {
		return UNCHUNKED_ENCODER.encodeToString(b);
	}

	static byte[] decode(String s) {
		return UNCHUNKED_ENCODER.decode(s);
	}

	static byte[] deflate(String s) {
		try {
			ByteArrayOutputStream b = new ByteArrayOutputStream();
			DeflaterOutputStream deflater = new DeflaterOutputStream(b, new Deflater(DEFLATED, true));
			deflater.write(s.getBytes(UTF_8));
			deflater.finish();
			return b.toByteArray();
		} catch (IOException e) {
			throw new SamlException("Unable to deflate string", e);
		}
	}

	static String inflate(byte[] b) {
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			InflaterOutputStream iout = new InflaterOutputStream(out, new Inflater(true));
			iout.write(b);
			iout.finish();
			return new String(out.toByteArray(), UTF_8);
		} catch (IOException e) {
			throw new SamlException("Unable to inflate string", e);
		}
	}
}
