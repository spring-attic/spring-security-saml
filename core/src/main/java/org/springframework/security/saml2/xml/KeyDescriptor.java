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

package org.springframework.security.saml2.xml;

import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import java.util.List;

public interface KeyDescriptor {

    /**
     * Returns at least one key. Per
     * https://www.oasis-open.org/committees/download.php/35391/sstc-saml-metadata-errata-2.0-wd-04-diff.pdf
     * Line 700
     * @return
     */
    List<KeyInfo> getKeyInfo();

    List<String> getEncryptionMethod();

    KeyType getUse();

}
