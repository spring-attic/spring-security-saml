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

package org.opensaml.compat;

import java.util.List;

import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.common.CacheableSAMLObject;
import org.opensaml.saml.saml2.common.TimeBoundSAMLObject;

public class SAML2Helper {

    /**
     * Checks to see if the given XMLObject is still valid. An XMLObject is valid if, and only if, itself and every
     * ancestral {@link TimeBoundSAMLObject} is valid.
     *
     * @param xmlObject the XML object tree to check
     *
     * @return true of the tree is valid, false if not
     */
    public static boolean isValid(XMLObject xmlObject) {
        if (xmlObject instanceof TimeBoundSAMLObject) {
            TimeBoundSAMLObject timeBoundObject = (TimeBoundSAMLObject) xmlObject;
            if (!timeBoundObject.isValid()) {
                return false;
            }
        }

        XMLObject parent = xmlObject.getParent();
        if (parent != null) {
            return isValid(parent);
        }

        return true;
    }

    /**
     * Gets the earliest expiration instant for a XMLObject. This method traverses the tree of SAMLObject rooted at the
     * given object and calculates the earliest expiration as the earliest of the following two items:
     * <ul>
     * <li>the earliest validUntil time on a {@link TimeBoundSAMLObject}</li>
     * <li>the shortest duration on a {@link CacheableSAMLObject} added to the current time</li>
     * </ul>
     *
     * @param xmlObject the XML object tree to get the earliest expiration time from
     *
     * @return the earliest expiration time
     */
    public static DateTime getEarliestExpiration(XMLObject xmlObject) {
        DateTime now = new DateTime();
        return getEarliestExpiration(xmlObject, null, now);
    }

    /**
     * Gets the earliest expiration instant within a metadata tree.
     *
     * @param xmlObject the metadata
     * @param earliestExpiration the earliest expiration instant
     * @param now when this method was called
     *
     * @return the earliest expiration instant within a metadata tree
     */
    public static DateTime getEarliestExpiration(XMLObject xmlObject, DateTime earliestExpiration, DateTime now) {

        // expiration time for a specific element
        DateTime elementExpirationTime;

        // Test duration based times
        if (xmlObject instanceof CacheableSAMLObject) {
            CacheableSAMLObject cacheInfo = (CacheableSAMLObject) xmlObject;

            if (cacheInfo.getCacheDuration() != null && cacheInfo.getCacheDuration().longValue() > 0) {
                elementExpirationTime = now.plus(cacheInfo.getCacheDuration().longValue());
                if (earliestExpiration == null) {
                    earliestExpiration = elementExpirationTime;
                } else {
                    if (elementExpirationTime != null && elementExpirationTime.isBefore(earliestExpiration)) {
                        earliestExpiration = elementExpirationTime;
                    }
                }
            }
        }

        // Test instant based times
        if (xmlObject instanceof TimeBoundSAMLObject) {
            TimeBoundSAMLObject timeBoundObject = (TimeBoundSAMLObject) xmlObject;
            elementExpirationTime = timeBoundObject.getValidUntil();
            if (earliestExpiration == null) {
                earliestExpiration = elementExpirationTime;
            } else {
                if (elementExpirationTime != null && elementExpirationTime.isBefore(earliestExpiration)) {
                    earliestExpiration = elementExpirationTime;
                }
            }
        }

        // Inspect children
        List<XMLObject> children = xmlObject.getOrderedChildren();
        if (children != null) {
            for (XMLObject child : xmlObject.getOrderedChildren()) {
                if (child != null) {
                    earliestExpiration = getEarliestExpiration(child, earliestExpiration, now);
                }
            }
        }

        return earliestExpiration;
    }
}