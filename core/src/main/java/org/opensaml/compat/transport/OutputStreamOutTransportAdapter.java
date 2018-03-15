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

import java.io.OutputStream;

/**
 * Adapter that allows a raw {@link OutputStream} to be used as an {@link OutTransport}.
 */
public class OutputStreamOutTransportAdapter extends BaseTransport implements OutTransport {

    /** The wrapped output stream. */
    private OutputStream outputStream;

    /**
     * Constructor.
     *
     * @param stream the output stream to adapt
     */
    public OutputStreamOutTransportAdapter(OutputStream stream) {
        outputStream = stream;
    }

    /** {@inheritDoc} */
    public OutputStream getOutgoingStream() {
        return outputStream;
    }

    /** {@inheritDoc} */
    public void setAttribute(String name, Object value) {
        super.setAttribute(name, value);
    }

    /** {@inheritDoc} */
    public void setCharacterEncoding(String encoding) {
        super.setCharacterEncoding(encoding);
    }

}
