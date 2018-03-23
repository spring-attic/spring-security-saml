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

package org.springframework.security.saml.metadata;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

import org.opensaml.compat.XMLHelper;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.core.io.Resource;

public class FileMetadataProvider extends MetadataMemoryProvider {

    /**
     * Constructor settings descriptor in parameter as the only entity available from this provider.
     */
    public FileMetadataProvider(String f) throws FileNotFoundException, UnmarshallingException {
        this(new FileInputStream(new File(f)));
    }

    public FileMetadataProvider(InputStream s) throws UnmarshallingException {
        super((XMLObject) XMLHelper.unmarshallMetadata(s));
    }

    public FileMetadataProvider(Resource r) throws IOException, UnmarshallingException {
        this(r.getInputStream());
    }



}
