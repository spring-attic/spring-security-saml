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

package org.opensaml.compat.transport;

import java.io.InputStream;

/**
 * Adapter that allows a raw {@link InputStream} to be used as an {@link InTransport}.
 */
public class InputStreamInTransportAdapter extends BaseTransport implements InTransport {

    /** The wrapped InputStream. */
    private InputStream inputStream;

    /**
     * Constructor.
     *
     * @param stream the input stream to adapt
     */
    public InputStreamInTransportAdapter(InputStream stream) {
        super();
        inputStream = stream;
    }

    /** {@inheritDoc} */
    public InputStream getIncomingStream() {
        return inputStream;
    }

}
