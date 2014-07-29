/*
 * Copyright 2010 Mandus Elfving
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
package org.opensaml.ws.transport.http.httpclient;

import org.apache.commons.httpclient.methods.RequestEntity;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * @author Mandus Elfving
 */
public class OutputStreamRequestEntity implements RequestEntity {

    private final ByteArrayOutputStream outputStream;
    private final String contentType;

    public OutputStreamRequestEntity(ByteArrayOutputStream outputStream) {
        this(outputStream, null);
    }

    public OutputStreamRequestEntity(ByteArrayOutputStream outputStream, String contentType) {
        this.outputStream = outputStream;
        this.contentType = contentType;
    }

    public boolean isRepeatable() {
        return true;
    }

    public void writeRequest(OutputStream outputStream) throws IOException {
        this.outputStream.writeTo(outputStream);
    }

    public long getContentLength() {
        return this.outputStream.size();
    }

    public String getContentType() {
        return this.contentType;
    }
}
