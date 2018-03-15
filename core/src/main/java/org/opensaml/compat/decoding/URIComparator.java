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

package org.opensaml.compat.decoding;

/**
 * Component for testing URI's as to equality.
 */
public interface URIComparator {

    /**
     * Compare two URI's (represented as strings) for equivalence.
     *
     * @param uri1 first URI to compare
     * @param uri2 second URI to compare
     *
     * @return true if the URI's are equivalent, false otherwise
     */
    public boolean compare(String uri1, String uri2);

}
