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

import java.util.List;

import org.opensaml.core.xml.XMLObject;

/**
 * A functional interface for XMLObjects that offer the ability
 * to evaluate validation rules.
 */
public interface ValidatingXMLObject extends XMLObject {

    /**
     * Gets the list of validators for this XMLObject or null if there is no list.
     *
     * @return the list of validators for this XMLObject
     */
    public List<Validator> getValidators();

    /**
     * Registers a validator for this XMLObject.
     *
     * @param validator the validator
     */
    public void registerValidator(Validator validator);

    /**
     * Deregisters a validator for this XMLObject.
     *
     * @param validator the validator
     */
    public void deregisterValidator(Validator validator);

    /**
     * Validates this XMLObject against all registered validators.
     *
     * @param validateDescendants true if all the descendants of this object should
     * be validated as well, false if not
     *
     * @throws ValidationException thrown if the element is not valid
     */
    public void validate(boolean validateDescendants) throws ValidationException;
}