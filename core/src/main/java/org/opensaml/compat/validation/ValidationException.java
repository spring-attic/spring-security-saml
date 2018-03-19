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

package org.opensaml.compat.validation;

/**
 * An exception indicating that a XMLObject is not valid.
 */
public class ValidationException extends Exception {

    /** Serial Version UID. */
    private static final long serialVersionUID = -8268522315645892798L;

    /**
     * Constructor.
     */
    public ValidationException() {
        super();
    }

    /**
     * Constructor.
     *
     * @param message exception message
     */
    public ValidationException(String message) {
        super(message);
    }

    /**
     * Constructor.
     *
     * @param wrappedException exception to be wrapped by this one
     */
    public ValidationException(Exception wrappedException) {
        super(wrappedException);
    }

    /**
     * Constructor.
     *
     * @param message exception message
     * @param wrappedException exception to be wrapped by this one
     */
    public ValidationException(String message, Exception wrappedException) {
        super(message, wrappedException);
    }
}