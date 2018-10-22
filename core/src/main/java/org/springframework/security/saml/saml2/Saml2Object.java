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

package org.springframework.security.saml.saml2;

public interface Saml2Object {
	/**
	 * Returns the underlying library representation of the metadata object.
	 * For example, if the underlying library is OpenSAML v3,
	 * this would return an object of class XMLObject.
	 *
	 * This method is not intended to preserve backwards compatibility
	 * if the underlying library is replaced. Rather this is for the cases where
	 * the Spring Security SAML abstraction layer does not sufficiently expose a feature
	 *
	 * When using this method, please open a github issue so that we can supplement the feature
	 * in a future release.  https://github.com/spring-projects/spring-security-saml
	 *
	 * @return the underlying implementation object. Currently an OpenSAML v3 object
	 */
	Object getImplementation();

	String getOriginalXML();

	String getOriginEntityId();

	String getDestinationEntityId();
}
