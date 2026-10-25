package com.urbantransport.gateway.integration;

import com.urbantransport.gateway.support.TestJwt;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class GatewayRoutingIT extends AbstractGatewayIT {

    private static Map<String, Object> cashier() {
        return TestJwt.claims("42", "CASHIER");
    }

    @Test
    @DisplayName("login es público y llega al servicio sin el prefijo /api/identity")
    void loginIsPublicAndStripsThePrefix() throws Exception {
        client.post().uri("/api/identity/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"user\":\"ale\"}")
                .exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.service").isEqualTo("identity");

        RecordedRequest forwarded = requestTo(IDENTITY);
        assertThat(forwarded.getMethod()).isEqualTo("POST");
        assertThat(forwarded.getPath()).isEqualTo("/auth/login");
    }

    @Test
    @DisplayName("en una ruta pública también se eliminan las cabeceras de identidad del cliente")
    void publicRouteStripsSpoofedHeaders() throws Exception {
        client.post().uri("/api/identity/auth/login")
                .header("X-User-Id", "999")
                .header("X-User-Role", "SYSTEM_ADMIN")
                .exchange()
                .expectStatus().isOk();

        RecordedRequest forwarded = requestTo(IDENTITY);
        assertThat(forwarded.getHeader("X-User-Id")).isNull();
        assertThat(forwarded.getHeader("X-User-Role")).isNull();
    }

    @Test
    @DisplayName("ruta protegida sin token -> 401 y el servicio no recibe nada")
    void protectedRouteWithoutTokenIsRejected() throws Exception {
        client.get().uri("/api/fleet/vehicles")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody()
                .jsonPath("$.status").isEqualTo(401)
                .jsonPath("$.message").isEqualTo("Missing bearer token")
                .jsonPath("$.path").isEqualTo("/api/fleet/vehicles");

        assertNoRequestTo(FLEET);
    }

    @Test
    @DisplayName("token válido: el servicio recibe la identidad del JWT, no la que mande el cliente")
    void validTokenForwardsIdentityHeaders() throws Exception {
        Map<String, Object> claims = TestJwt.claims("42", "BRANCH_ADMIN");
        claims.put("branchId", "7");
        String authorization = bearer(claims);

        client.get().uri("/api/fleet/vehicles?plate=P123")
                .header(HttpHeaders.AUTHORIZATION, authorization)
                .header("X-User-Id", "999")
                .header("X-Customer-Id", "evil")
                .exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.service").isEqualTo("fleet");

        RecordedRequest forwarded = requestTo(FLEET);
        assertThat(forwarded.getPath()).isEqualTo("/vehicles?plate=P123");
        assertThat(forwarded.getHeader("X-User-Id")).isEqualTo("42");
        assertThat(forwarded.getHeader("X-User-Role")).isEqualTo("BRANCH_ADMIN");
        assertThat(forwarded.getHeader("X-Branch-Id")).isEqualTo("7");
        assertThat(forwarded.getHeader("X-Customer-Id")).isNull();
        assertThat(forwarded.getHeader(HttpHeaders.AUTHORIZATION)).isEqualTo(authorization);
    }

    @Test
    @DisplayName("/api/*/internal/** nunca se expone, ni con token válido")
    void internalRoutesAreNotExposed() throws Exception {
        client.get().uri("/api/fleet/internal/vehicles")
                .header(HttpHeaders.AUTHORIZATION, bearer(cashier()))
                .exchange()
                .expectStatus().isNotFound()
                .expectBody().jsonPath("$.message").isEqualTo("Route not found");

        assertNoRequestTo(FLEET);
    }

    /*@ParameterizedTest
    @ValueSource(strings = {"/api//fleet/vehicles", "/api/fleet/../internal/vehicles"})
    @DisplayName("rutas con // o .. -> 400")
    void suspiciousPathsAreRejected(String path) throws Exception {
        client.get().uri(path)
                .header(HttpHeaders.AUTHORIZATION, bearer(cashier()))
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.message").isEqualTo("Invalid request path");

        assertNoRequestTo(FLEET);
    }*/

    @Test
    @DisplayName("el OpenAPI de cada servicio es público y se reescribe a /v3/api-docs")
    void apiDocsAreRewrittenAndPublic() throws Exception {
        client.get().uri("/docs/fleet/v3/api-docs")
                .exchange()
                .expectStatus().isOk();

        assertThat(requestTo(FLEET).getPath()).isEqualTo("/v3/api-docs");
    }

    @Test
    @DisplayName("servicio no registrado -> 404 en JSON (el filtro JWT solo corre en rutas que existen)")
    void unknownServiceIsNotFound() {
        client.get().uri("/api/unknown/things")
                .exchange()
                .expectStatus().isNotFound()
                .expectBody()
                .jsonPath("$.status").isEqualTo(404)
                .jsonPath("$.path").isEqualTo("/api/unknown/things");
    }

    @Test
    @DisplayName("un error del servicio destino pasa tal cual (el gateway no lo reescribe)")
    void downstreamErrorsPassThroughUntouched() {
        client.get().uri("/api/fleet/boom")
                .header(HttpHeaders.AUTHORIZATION, bearer(cashier()))
                .exchange()
                .expectStatus().isEqualTo(500)
                .expectBody().jsonPath("$.error").isEqualTo("service-side");
    }

    @Test
    @DisplayName("servicio caído (conexión rechazada) -> 503 con JSON uniforme")
    void unavailableServiceReturns503() {
        client.get().uri("/api/reporting/sales")
                .header(HttpHeaders.AUTHORIZATION, bearer(cashier()))
                .exchange()
                .expectStatus().isEqualTo(503)
                .expectBody()
                .jsonPath("$.status").isEqualTo(503)
                .jsonPath("$.message").isEqualTo("Service unavailable");
    }

    @Test
    @DisplayName("servicio que no responde dentro del response-timeout -> 504")
    void slowServiceReturnsGatewayTimeout() {
        client.get().uri("/api/finance/slow")
                .header(HttpHeaders.AUTHORIZATION, bearer(cashier()))
                .exchange()
                .expectStatus().isEqualTo(504)
                .expectBody().jsonPath("$.status").isEqualTo(504);
    }

    @Test
    @DisplayName("preflight CORS desde el origen de Angular pasa sin token")
    void corsPreflightIsAnsweredWithoutToken() throws Exception {
        client.options().uri("/api/fleet/vehicles")
                .header(HttpHeaders.ORIGIN, "http://localhost:4200")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "authorization")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "http://localhost:4200");

        assertNoRequestTo(FLEET);
    }

    @Test
    @DisplayName("actuator/health responde sin token")
    void healthEndpointIsAvailable() {
        client.get().uri("/actuator/health")
                .exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.status").isEqualTo("UP");
    }
}