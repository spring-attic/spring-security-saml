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
package org.springframework.security.saml.util;

import java.net.URISyntaxException;

import org.springframework.security.saml.SamlException;

import org.apache.http.client.utils.URIBuilder;

public class StringUtils {

	public static String getNCNameString(String value) {
		if (value == null) {
			return null;
		}
		String cleanValue = value.replaceAll("[^a-zA-Z0-9-_.]", "_");
		if (cleanValue.startsWith("-")) {
			cleanValue = "_" + cleanValue.substring(1);
		}
		return cleanValue;
	}

	public static URIBuilder fromString(String url) {
		try {
			return new URIBuilder(url);
		} catch (URISyntaxException e) {
			throw new SamlException(e);
		}
	}

	public static String addAliasPath(String path, String alias) {
		return stripEndingSlases(path) + "/alias/" + alias;
	}

	public static String stripEndingSlases(String path) {
		while (path.endsWith("/")) {
			path = path.substring(0, path.length() - 1);
		}
		return path;
	}

	public static String appendSlash(String path) {
		if (!path.endsWith("/")) {
			path = path + "/";
		}
		return path;
	}

	public static String prependSlash(String result) {
		if (!result.startsWith("/")) {
			result = "/" + result;
		}
		return result;
	}

	public static String stripSlashes(String path) {
		path = stripStartingSlashes(path);
		path = stripEndingSlases(path);
		return path;
	}

	public static String stripStartingSlashes(String path) {
		while (path.startsWith("/")) {
			path = path.substring(1);
		}
		return path;
	}

}
