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

import org.opensaml.core.xml.XMLObject;

/**
 * An interface for classes that implement rules for checking the
 * validity of a XMLObjects.
 *
 * @param <XMLObjectType> type of XML object that will be validated
 */
public interface Validator<XMLObjectType extends XMLObject> {

    /**
     * Checks to see if a XMLObject is valid.
     *
     * @param xmlObject the XMLObject to validate
     *
     * @throws ValidationException thrown if the element is not valid
     */
    public void validate(XMLObjectType xmlObject) throws ValidationException;
}