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
package org.springframework.security.saml.validation;

import java.util.Arrays;

import org.springframework.security.saml.SamlException;

public class ValidationException extends SamlException {

	private ValidationResult errors;

	public ValidationException(String message, ValidationResult errors) {
		super(message);
		this.errors = errors;
	}

	public ValidationException(String message, Throwable cause, ValidationResult errors) {
		super(message, cause);
		this.errors = errors;
	}

	public ValidationResult getErrors() {
		return errors;
	}

	@Override
	public String getMessage() {
		StringBuffer sb = new StringBuffer("SAML Validation Errors:");
		for (ValidationResult.ValidationError error : errors.getErrors()) {
			sb.append(" ");
			sb.append(error.getMessage());
			sb.append(";");
		}
		return sb.toString();
	}

	@Override
	public String toString() {
		final StringBuffer sb = new StringBuffer(" ValidationException{");
		sb.append("errors=").append(Arrays.toString(errors.getErrors().toArray()));
		sb.append('}');
		return sb.toString();
	}
}
