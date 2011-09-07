package org.opensaml.ws.transport.http;

/**
 * Interface marks HTTP In Transports which can contain URL at which is the reception of data done.
 */
public interface LocationAwareInTransport {

    public String getLocalAddress();

}
