package com.urbantransport.gateway.support;

import com.urbantransport.gateway.exception.GatewayException;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;

public final class GatewayAssertions {

    private GatewayAssertions() {
    }

    /** Verifica que el Mono termine en GatewayException con el status y mensaje esperados. */
    public static void assertGatewayError(Mono<?> mono, HttpStatus status, String message) {
        StepVerifier.create(mono)
                .expectErrorSatisfies(error -> {
                    assertThat(error).isInstanceOf(GatewayException.class);
                    GatewayException exception = (GatewayException) error;
                    assertThat(exception.getStatus()).isEqualTo(status);
                    assertThat(exception.getMessage()).isEqualTo(message);
                })
                .verify();
    }
}
