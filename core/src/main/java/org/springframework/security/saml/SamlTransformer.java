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

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.spi.Defaults;

public interface SamlTransformer {

    String toXml(Saml2Object saml2Object);

    default Saml2Object resolve(String xml, List<SimpleKey> trustedKeys) {
        return resolve(xml.getBytes(StandardCharsets.UTF_8), trustedKeys);
    }

    Saml2Object resolve(byte[] xml, List<SimpleKey> trustedKeys);

    /**
     * Deflates and base64 encodes the SAML message readying it for transport.
     * If the result is used as a query parameter, it still has to be URL encoded.
     * @param s - original string
     * @return deflated and base64 encoded string
     */
    String samlEncode(String s);

    /**
     * base64 decodes and inflates the SAML message.
     * @param s base64 encoded deflated string
     * @return the original string
     */
    String samlDecode(String s);

    Defaults getDefaults();

    MetadataResolver getMetadataResolver();
}
