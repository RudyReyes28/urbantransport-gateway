package com.urbantransport.gateway.exception;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ResponseStatusException;
import reactor.test.StepVerifier;
import tools.jackson.databind.json.JsonMapper;

import java.net.ConnectException;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GatewayErrorHandlerTest {

    private static final String PATH = "/api/fleet/vehicles";

    private final JsonMapper jsonMapper = JsonMapper.builder().build();
    private GatewayErrorHandler handler;
    private MockServerWebExchange exchange;

    @BeforeEach
    void setUp() {
        handler = new GatewayErrorHandler(jsonMapper);
        exchange = MockServerWebExchange.from(MockServerHttpRequest.get(PATH));
    }

    @Test
    @DisplayName("GatewayException: usa su status y mensaje")
    void gatewayExceptionKeepsItsStatusAndMessage() {
        handle(new GatewayException(HttpStatus.UNAUTHORIZED, "Missing bearer token"));

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(exchange.getResponse().getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
        Map<?, ?> body = body();
        assertThat(body.get("status")).isEqualTo(401);
        assertThat(body.get("message")).isEqualTo("Missing bearer token");
        assertThat(body.get("path")).isEqualTo(PATH);
        assertThat(body.get("timestamp")).isNotNull();
    }

    @Test
    @DisplayName("ResponseStatusException con razón: usa la razón")
    void responseStatusExceptionWithReason() {
        handle(new ResponseStatusException(HttpStatus.FORBIDDEN, "Nope"));

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(body().get("message")).isEqualTo("Nope");
    }

    @Test
    @DisplayName("ResponseStatusException sin razón: usa la frase estándar del status")
    void responseStatusExceptionWithoutReason() {
        handle(new ResponseStatusException(HttpStatus.NOT_FOUND));

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(body().get("message")).isEqualTo("Not Found");
    }

    @Test
    @DisplayName("ResponseStatusException con código no estándar: responde 500")
    void responseStatusExceptionWithNonStandardCodeBecomes500() {
        handle(new ResponseStatusException(HttpStatusCode.valueOf(499)));

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(body().get("status")).isEqualTo(500);
    }

    @Test
    @DisplayName("ConnectException directa -> 503")
    void connectExceptionBecomesServiceUnavailable() {
        handle(new ConnectException("refused"));

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(body().get("message")).isEqualTo("Service unavailable");
    }

    @Test
    @DisplayName("ConnectException como causa anidada -> 503")
    void nestedConnectExceptionBecomesServiceUnavailable() {
        Throwable wrapped = new RuntimeException("outer", new IllegalStateException("middle", new ConnectException("refused")));

        handle(wrapped);

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    }

    @Test
    @DisplayName("causa que se apunta a sí misma no provoca bucle infinito")
    void selfReferencingCauseDoesNotLoop() {
        Throwable selfCause = new RuntimeException("loop") {
            @Override
            public synchronized Throwable getCause() {
                return this;
            }
        };

        handle(selfCause);

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Test
    @DisplayName("error inesperado -> 500 genérico sin filtrar detalles internos")
    void unexpectedErrorDoesNotLeakDetails() {
        handle(new IllegalStateException("jdbc:postgresql://db-interna:5432 password=secreto"));

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(body().get("message")).isEqualTo("Unexpected gateway error");
        assertThat(rawBody()).doesNotContain("secreto").doesNotContain("db-interna");
    }

    @Test
    @DisplayName("si la respuesta ya fue enviada, propaga el error original")
    void committedResponseReturnsOriginalError() {
        exchange.getResponse().setComplete().block();
        RuntimeException original = new RuntimeException("late failure");

        StepVerifier.create(handler.handle(exchange, original))
                .expectErrorMatches(error -> error == original)
                .verify();
    }

    @Test
    @DisplayName("si no se puede serializar el ErrorResponse, responde un JSON de respaldo")
    void serializationFailureFallsBackToStaticBody() {
        JsonMapper failing = mock(JsonMapper.class);
        when(failing.writeValueAsBytes(any())).thenThrow(new IllegalStateException("boom"));
        GatewayErrorHandler fallbackHandler = new GatewayErrorHandler(failing);

        StepVerifier.create(fallbackHandler.handle(exchange, new GatewayException(HttpStatus.BAD_REQUEST, "x")))
                .verifyComplete();

        assertThat(rawBody()).contains("Error serializing response");
    }

    // ---------------------------------------------------------------- helpers

    private void handle(Throwable error) {
        StepVerifier.create(handler.handle(exchange, error)).verifyComplete();
    }

    private String rawBody() {
        return exchange.getResponse().getBodyAsString().block();
    }

    private Map<?, ?> body() {
        return jsonMapper.readValue(rawBody(), Map.class);
    }
}
