package org.springframework.security.saml;

import org.opensaml.common.SAMLException;

/**
 * SAML exception which contains status code which should be returned to the caller as part of status message.
 */
public class SAMLStatusException extends SAMLException {

    private String statusCode;
    private String statusMessage;

    public SAMLStatusException(String statusCode, String message) {
        super(message);
        this.statusCode = statusCode;
        this.statusMessage = message;
    }

    public SAMLStatusException(String statusCode, Exception wrappedException) {
        super(wrappedException);
        this.statusCode = statusCode;
        this.statusMessage = wrappedException.getMessage();
    }

    public SAMLStatusException(String statusCode, String message, Exception wrappedException) {
        super(message, wrappedException);
        this.statusCode = statusCode;
        this.statusMessage = message;
    }

    public String getStatusCode() {
        return statusCode;
    }

    public String getStatusMessage() {
        return statusMessage;
    }

}
