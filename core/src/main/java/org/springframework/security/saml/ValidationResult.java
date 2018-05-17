/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.springframework.security.saml;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class ValidationResult {

    private boolean success = false;
    private List<ValidationError> errors = new LinkedList<>();

    public boolean isSuccess() {
        return success;
    }

    public ValidationResult setSuccess(boolean success) {
        this.success = success;
        return this;
    }

    public List<ValidationError> getErrors() {
        return Collections.unmodifiableList(errors);
    }

    public ValidationResult setErrors(List<ValidationError> errors) {
        this.errors.clear();
        this.errors.addAll(errors);
        return this;
    }

    public ValidationResult addError(ValidationError error) {
        this.errors.add(error);
        return this;
    }

    public static class ValidationError {
        private final int code;
        private final String message;

        public ValidationError(int code, String message) {
            this.code = code;
            this.message = message;
        }
    }
}
