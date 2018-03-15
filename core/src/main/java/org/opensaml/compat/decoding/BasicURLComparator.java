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

import org.opensaml.util.SimpleURLCanonicalizer;

/**
 * A basic implementation of {@link URIComparator} that compares
 * URL's by canonicalizing them as per {@link SimpleURLCanonicalizer},
 * and then compares the resulting string representations for equality
 * using String equals(). If {link {@link #isCaseInsensitive()} is true,
 * then the equality test is instead performed using String equalsIgnoreCase().
 */
public class BasicURLComparator implements URIComparator {

    /** The case-insensitivity flag. */
    private boolean caseInsensitive;

    /**
     * Get the case-insensitivity flag value.
     * @return Returns the caseInsensitive.
     */
    public boolean isCaseInsensitive() {
        return caseInsensitive;
    }

    /**
     * Set the case-insensitivity flag value.
     * @param flag The caseInsensitive to set.
     */
    public void setCaseInsensitive(boolean flag) {
        caseInsensitive = flag;
    }

    /** {@inheritDoc} */
    public boolean compare(String uri1, String uri2) {
        if (uri1 == null) {
            return uri2 == null;
        } else if (uri2 == null) {
            return uri1 == null;
        } else {
            String uri1Canon = SimpleURLCanonicalizer.canonicalize(uri1);
            String uri2Canon = SimpleURLCanonicalizer.canonicalize(uri2);
            if (isCaseInsensitive()) {
                return uri1Canon.equalsIgnoreCase(uri2Canon);
            } else {
                return uri1Canon.equals(uri2Canon);
            }
        }
    }

}
