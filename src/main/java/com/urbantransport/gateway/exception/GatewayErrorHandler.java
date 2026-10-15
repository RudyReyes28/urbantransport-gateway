package com.urbantransport.gateway.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.webflux.error.ErrorWebExceptionHandler;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import tools.jackson.databind.json.JsonMapper;

import java.net.ConnectException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

/** Convierte cualquier error del gateway en un JSON uniforme sin filtrar detalles internos. */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class GatewayErrorHandler implements ErrorWebExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GatewayErrorHandler.class);
    private static final String FALLBACK_BODY =
            "{\"status\":500,\"message\":\"Error serializing response\",\"path\":\"/\"}";

    private final JsonMapper jsonMapper;

    public GatewayErrorHandler(JsonMapper jsonMapper) {
        this.jsonMapper = jsonMapper;
    }

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {
        ServerHttpResponse response = exchange.getResponse();
        if (response.isCommitted()) {
            return Mono.error(ex);
        }

        HttpStatus status;
        String message;
        if (ex instanceof GatewayException gatewayException) {
            status = gatewayException.getStatus();
            message = gatewayException.getMessage();
        } else if (ex instanceof ResponseStatusException statusException) {
            HttpStatus resolved = HttpStatus.resolve(statusException.getStatusCode().value());
            status = resolved == null ? HttpStatus.INTERNAL_SERVER_ERROR : resolved;
            message = statusException.getReason() != null ? statusException.getReason() : status.getReasonPhrase();
        } else if (isConnectionFailure(ex)) {
            status = HttpStatus.SERVICE_UNAVAILABLE;
            message = "Service unavailable";
        } else {
            status = HttpStatus.INTERNAL_SERVER_ERROR;
            message = "Unexpected gateway error";
        }

        String path = exchange.getRequest().getPath().value();
        if (status.is5xxServerError()) {
            log.error("Gateway error status={} path={}", status.value(), path, ex);
        } else {
            log.warn("Gateway error status={} path={} message={}", status.value(), path, message);
        }

        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        byte[] body = serialize(new ErrorResponse(Instant.now(), status.value(), message, path));
        return response.writeWith(Mono.just(response.bufferFactory().wrap(body)));
    }

    private boolean isConnectionFailure(Throwable ex) {
        for (Throwable current = ex; current != null; current = current.getCause()) {
            if (current instanceof ConnectException) {
                return true;
            }
            if (current.getCause() == current) {
                break;
            }
        }
        return false;
    }

    private byte[] serialize(ErrorResponse body) {
        try {
            return jsonMapper.writeValueAsBytes(body);
        } catch (Exception exception) {
            return FALLBACK_BODY.getBytes(StandardCharsets.UTF_8);
        }
    }
}
