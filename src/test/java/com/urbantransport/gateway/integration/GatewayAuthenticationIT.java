package com.urbantransport.gateway.integration;

import com.urbantransport.gateway.support.TestJwt;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class GatewayAuthenticationIT extends AbstractGatewayIT {

    private static final String INVALID = "Invalid or expired token";
    private static final TestJwt ATTACKER = new TestJwt();

    @Test
    @DisplayName("token vencido -> 401")
    void expiredToken() throws Exception {
        Map<String, Object> claims = TestJwt.claims("1", "CASHIER");
        claims.put("exp", Instant.now().getEpochSecond() - 60);

        assertRejected(bearer(claims), 401, INVALID);
    }

    @Test
    @DisplayName("token firmado con otra llave -> 401")
    void foreignSignature() throws Exception {
        String forged = "Bearer " + ATTACKER.sign(TestJwt.claims("1", "SYSTEM_ADMIN"));

        assertRejected(forged, 401, INVALID);
    }

    @Test
    @DisplayName("alg=HS256 -> 401")
    void unsupportedAlgorithm() throws Exception {
        String token = ISSUER.sign(Map.of("alg", "HS256", "typ", "JWT"), TestJwt.claims("1", "CASHIER"));

        assertRejected("Bearer " + token, 401, INVALID);
    }

    @Test
    @DisplayName("token basura -> 401")
    void garbageToken() throws Exception {
        assertRejected("Bearer esto.no.es-un-jwt", 401, INVALID);
    }

    @Test
    @DisplayName("esquema distinto de Bearer -> 401")
    void nonBearerScheme() throws Exception {
        assertRejected("Basic dXNlcjpwYXNz", 401, "Missing bearer token");
    }

    @Test
    @DisplayName("rol no permitido -> 403")
    void roleNotAllowed() throws Exception {
        assertRejected(bearer(TestJwt.claims("1", "HACKER")), 403, "Invalid role");
    }

    @Test
    @DisplayName("token válido sin user_id/sub -> 403")
    void missingClaims() throws Exception {
        Map<String, Object> claims = TestJwt.claims("1", "CASHIER");
        claims.remove("user_id");

        assertRejected(bearer(claims), 403, "Required claims not found");
    }

    @Test
    @DisplayName("la llave pública se consulta una sola vez aunque lleguen muchas peticiones")
    void publicKeyIsCachedAcrossRequests() {
        int before = PUBLIC_KEY_FETCHES.get();

        for (int i = 0; i < 5; i++) {
            client.get().uri("/api/fleet/vehicles")
                    .header(HttpHeaders.AUTHORIZATION, bearer(TestJwt.claims("1", "CASHIER")))
                    .exchange()
                    .expectStatus().isOk();
        }

        // <= 1: si otro test ya la había cargado, ni siquiera hay una consulta nueva
        assertThat(PUBLIC_KEY_FETCHES.get()).isLessThanOrEqualTo(before + 1);
    }

    @Test
    @DisplayName("si identity rota su llave, el gateway la recarga y acepta los tokens nuevos")
    void rotatedKeyIsPickedUp() {
        client.get().uri("/api/fleet/vehicles")      // asegura la llave vieja en caché
                .header(HttpHeaders.AUTHORIZATION, bearer(TestJwt.claims("1", "CASHIER")))
                .exchange()
                .expectStatus().isOk();

        TestJwt rotated = new TestJwt();
        ACTIVE_KEY.set(rotated);                      // identity ya publica la llave nueva

        client.get().uri("/api/fleet/vehicles")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + rotated.sign(TestJwt.claims("1", "CASHIER")))
                .exchange()
                .expectStatus().isOk();
    }

    // ------------------------------------------------------------------ helper

    private void assertRejected(String authorization, int status, String message) throws Exception {
        client.get().uri("/api/fleet/vehicles")
                .header(HttpHeaders.AUTHORIZATION, authorization)
                .exchange()
                .expectStatus().isEqualTo(status)
                .expectBody()
                .jsonPath("$.status").isEqualTo(status)
                .jsonPath("$.message").isEqualTo(message)
                .jsonPath("$.path").isEqualTo("/api/fleet/vehicles");

        assertNoRequestTo(FLEET);
    }
}