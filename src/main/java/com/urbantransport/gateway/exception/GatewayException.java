package com.urbantransport.gateway.exception;

import org.springframework.http.HttpStatus;

/** Error controlado del gateway con el código HTTP que debe recibir el cliente. */
public class GatewayException extends RuntimeException {

    private final HttpStatus status;

    public GatewayException(HttpStatus status, String message) {
        super(message);
        this.status = status;
    }

    public HttpStatus getStatus() {
        return status;
    }
}
