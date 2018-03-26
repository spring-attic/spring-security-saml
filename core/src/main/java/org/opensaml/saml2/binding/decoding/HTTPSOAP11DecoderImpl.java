/*
 * Copyright 2010 Vladimir Schaefer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.opensaml.saml2.binding.decoding;

import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPSOAP11Decoder;

/**
 * Custom implementation of the decoder which takes into account user HTTPInput method
 * for determining correct expected URI.
 */
public class HTTPSOAP11DecoderImpl extends HTTPSOAP11Decoder {

    public HTTPSOAP11DecoderImpl(ParserPool pool) {
        super();
        setParserPool(pool);
    }

}