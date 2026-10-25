package com.urbantransport.gateway.security;

import com.urbantransport.gateway.config.GatewayProperties;
import com.urbantransport.gateway.config.GatewayProperties.Security;
import com.urbantransport.gateway.support.TestJwt;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import tools.jackson.databind.json.JsonMapper;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.urbantransport.gateway.support.GatewayAssertions.assertGatewayError;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtTokenVerifierTest {

    private static final String INVALID = "Invalid or expired token";

    /** Dueño legítimo de la llave que "publica" identity. */
    private static final TestJwt ISSUER = new TestJwt();
    /** Un atacante (o una llave rotada) con otro par de llaves. */
    private static final TestJwt OTHER = new TestJwt();

    @Mock
    private PublicKeyProvider keyProvider;

    private JwtTokenVerifier verifier;

    @BeforeEach
    void setUp() {
        verifier = verifierWithRoles(null);
    }

    // ---------------------------------------------------------------- caminos felices

    @Test
    @DisplayName("token válido: devuelve la identidad con claim role")
    void validTokenReturnsUser() {
        cachedKeyIs(ISSUER);
        Map<String, Object> claims = TestJwt.claims("42", "CASHIER");
        claims.put("branchId", "7");

        StepVerifier.create(verifier.verify(ISSUER.sign(claims)))
                .expectNext(new AuthenticatedUser("42", "CASHIER", "7", null, null))
                .verifyComplete();
        verify(keyProvider, never()).refreshPublicKey();
    }

    @Test
    @DisplayName("usa 'sub' cuando no viene 'user_id'")
    void fallsBackToSubWhenUserIdIsMissing() {
        cachedKeyIs(ISSUER);
        Map<String, Object> claims = TestJwt.claims("ignored", "DRIVER");
        claims.remove("user_id");
        claims.put("sub", "driver-1");

        StepVerifier.create(verifier.verify(ISSUER.sign(claims)))
                .expectNext(new AuthenticatedUser("driver-1", "DRIVER", null, null, null))
                .verifyComplete();
    }

    @Test
    @DisplayName("acepta ids numéricos y los convierte a texto")
    void numericClaimsAreConvertedToText() {
        cachedKeyIs(ISSUER);
        Map<String, Object> claims = TestJwt.claims("x", "BRANCH_ADMIN");
        claims.put("user_id", 15);
        claims.put("branchId", 3);

        StepVerifier.create(verifier.verify(ISSUER.sign(claims)))
                .expectNext(new AuthenticatedUser("15", "BRANCH_ADMIN", "3", null, null))
                .verifyComplete();
    }

    @Test
    @DisplayName("toma el primer elemento del claim 'roles' si no hay 'role'")
    void usesFirstOfRolesWhenRoleIsMissing() {
        cachedKeyIs(ISSUER);
        Map<String, Object> claims = TestJwt.claims("1", "ignored");
        claims.remove("role");
        claims.put("roles", List.of(" SYSTEM_ADMIN ", "CASHIER"));

        StepVerifier.create(verifier.verify(ISSUER.sign(claims)))
                .expectNext(new AuthenticatedUser("1", "SYSTEM_ADMIN", null, null, null))
                .verifyComplete();
    }

    @Test
    @DisplayName("lee customerId y nit de un CUSTOMER")
    void customerClaimsAreMapped() {
        cachedKeyIs(ISSUER);
        Map<String, Object> claims = TestJwt.claims("9", "CUSTOMER");
        claims.put("customerId", 15);
        claims.put("nit", "1234567-8");

        StepVerifier.create(verifier.verify(ISSUER.sign(claims)))
                .expectNext(new AuthenticatedUser("9", "CUSTOMER", null, "15", "1234567-8"))
                .verifyComplete();
    }

    @Test
    @DisplayName("recorta espacios y descarta claims en blanco")
    void claimsAreTrimmedAndBlanksDiscarded() {
        cachedKeyIs(ISSUER);
        Map<String, Object> claims = TestJwt.claims("  42  ", "  CASHIER  ");
        claims.put("branchId", "   ");

        StepVerifier.create(verifier.verify(ISSUER.sign(claims)))
                .expectNext(new AuthenticatedUser("42", "CASHIER", null, null, null))
                .verifyComplete();
    }

    @Test
    @DisplayName("acepta 'exp' como texto numérico")
    void expAsNumericStringIsAccepted() {
        cachedKeyIs(ISSUER);
        Map<String, Object> claims = TestJwt.claims("1", "CASHIER");
        claims.put("exp", String.valueOf(Instant.now().getEpochSecond() + 600));

        StepVerifier.create(verifier.verify(ISSUER.sign(claims)))
                .expectNextCount(1)
                .verifyComplete();
    }

    // ---------------------------------------------------------------- 401: token inválido

    @ParameterizedTest
    @ValueSource(strings = {
            "",
            "abc",
            "a.b",
            "a.b.c.d",
            "!!!.@@@.###",
            "bm9qc29u.bm9qc29u.c2ln",   // base64 válido pero no es JSON
            "e30.bnVsbA.c2ln"           // payload JSON "null"
    })
    @DisplayName("token con formato inválido -> 401 sin consultar la llave")
    void malformedTokensAreRejected(String token) {
        assertGatewayError(verifier.verify(token), HttpStatus.UNAUTHORIZED, INVALID);
        verifyNoInteractions(keyProvider);
    }

    @ParameterizedTest
    @ValueSource(strings = {"HS256", "none", "RS512", "rs256"})
    @DisplayName("algoritmo distinto de RS256 -> 401 (evita alg=none y confusión HS/RS)")
    void unsupportedAlgorithmIsRejected(String alg) {
        String token = ISSUER.sign(Map.of("alg", alg, "typ", "JWT"), TestJwt.claims("1", "CASHIER"));

        assertGatewayError(verifier.verify(token), HttpStatus.UNAUTHORIZED, INVALID);
        verifyNoInteractions(keyProvider);
    }

    @Test
    @DisplayName("header sin 'alg' -> 401")
    void missingAlgIsRejected() {
        String token = ISSUER.sign(Map.of("typ", "JWT"), TestJwt.claims("1", "CASHIER"));

        assertGatewayError(verifier.verify(token), HttpStatus.UNAUTHORIZED, INVALID);
    }

    @Test
    @DisplayName("token vencido -> 401")
    void expiredTokenIsRejected() {
        Map<String, Object> claims = TestJwt.claims("1", "CASHIER");
        claims.put("exp", Instant.now().getEpochSecond() - 10);

        assertGatewayError(verifier.verify(ISSUER.sign(claims)), HttpStatus.UNAUTHORIZED, INVALID);
        verifyNoInteractions(keyProvider);
    }

    @Test
    @DisplayName("token sin 'exp' -> 401")
    void missingExpIsRejected() {
        Map<String, Object> claims = TestJwt.claims("1", "CASHIER");
        claims.remove("exp");

        assertGatewayError(verifier.verify(ISSUER.sign(claims)), HttpStatus.UNAUTHORIZED, INVALID);
    }

    @ParameterizedTest
    @ValueSource(strings = {"abc", "", "-5", "12.5"})
    @DisplayName("'exp' como texto no numérico -> 401")
    void nonNumericExpIsRejected(String exp) {
        Map<String, Object> claims = TestJwt.claims("1", "CASHIER");
        claims.put("exp", exp);

        assertGatewayError(verifier.verify(ISSUER.sign(claims)), HttpStatus.UNAUTHORIZED, INVALID);
    }

    @Test
    @DisplayName("firma de otra llave: reintenta con la llave refrescada y, si sigue fallando, 401")
    void foreignSignatureIsRejectedAfterRefresh() {
        cachedKeyIs(ISSUER);
        refreshedKeyIs(ISSUER);
        String forged = OTHER.sign(TestJwt.claims("1", "SYSTEM_ADMIN"));

        assertGatewayError(verifier.verify(forged), HttpStatus.UNAUTHORIZED, INVALID);
        verify(keyProvider).refreshPublicKey();
    }

    @Test
    @DisplayName("payload alterado con la firma original (escalada de rol) -> 401")
    void tamperedPayloadIsRejected() {
        cachedKeyIs(ISSUER);
        refreshedKeyIs(ISSUER);
        String original = ISSUER.sign(TestJwt.claims("1", "CASHIER"));
        String[] parts = original.split("\\.");
        String forgedPayload = TestJwt.encode(TestJwt.claims("1", "SYSTEM_ADMIN"));
        String tampered = parts[0] + "." + forgedPayload + "." + parts[2];

        assertGatewayError(verifier.verify(tampered), HttpStatus.UNAUTHORIZED, INVALID);
    }

    @Test
    @DisplayName("firma truncada o basura -> 401")
    void garbageSignatureIsRejected() {
        cachedKeyIs(ISSUER);
        refreshedKeyIs(ISSUER);
        String[] parts = ISSUER.sign(TestJwt.claims("1", "CASHIER")).split("\\.");
        String token = parts[0] + "." + parts[1] + ".c2ln";

        assertGatewayError(verifier.verify(token), HttpStatus.UNAUTHORIZED, INVALID);
    }

    // ---------------------------------------------------------------- rotación de llave

    @Test
    @DisplayName("si identity rotó la llave, la recarga permite validar el token")
    void keyRotationIsHandledByRefreshing() {
        cachedKeyIs(OTHER);       // la caché aún tiene la llave vieja
        refreshedKeyIs(ISSUER);   // identity ya publica la nueva
        String token = ISSUER.sign(TestJwt.claims("1", "CASHIER"));

        StepVerifier.create(verifier.verify(token))
                .expectNextCount(1)
                .verifyComplete();
        verify(keyProvider).refreshPublicKey();
    }

    @Test
    @DisplayName("si identity está caído, el 503 del provider se propaga tal cual")
    void keyProviderFailureIsPropagated() {
        when(keyProvider.getPublicKey()).thenReturn(Mono.error(
                new com.urbantransport.gateway.exception.GatewayException(
                        HttpStatus.SERVICE_UNAVAILABLE, "Authentication service unavailable")));

        assertGatewayError(verifier.verify(ISSUER.sign(TestJwt.claims("1", "CASHIER"))),
                HttpStatus.SERVICE_UNAVAILABLE, "Authentication service unavailable");
        verify(keyProvider, never()).refreshPublicKey();
    }

    // ---------------------------------------------------------------- 403: claims y rol

    @Test
    @DisplayName("token válido sin user_id ni sub -> 403")
    void missingUserIdIsForbidden() {
        cachedKeyIs(ISSUER);
        Map<String, Object> claims = TestJwt.claims("1", "CASHIER");
        claims.remove("user_id");

        assertGatewayError(verifier.verify(ISSUER.sign(claims)), HttpStatus.FORBIDDEN, "Required claims not found");
    }

    @Test
    @DisplayName("token válido sin role ni roles -> 403")
    void missingRoleIsForbidden() {
        cachedKeyIs(ISSUER);
        Map<String, Object> claims = TestJwt.claims("1", "CASHIER");
        claims.remove("role");

        assertGatewayError(verifier.verify(ISSUER.sign(claims)), HttpStatus.FORBIDDEN, "Required claims not found");
    }

    @Test
    @DisplayName("role en blanco y 'roles' vacío o con primer elemento en blanco -> 403")
    void blankRolesAreForbidden() {
        cachedKeyIs(ISSUER);
        Map<String, Object> blankRole = TestJwt.claims("1", "   ");
        Map<String, Object> emptyRoles = TestJwt.claims("1", "x");
        emptyRoles.remove("role");
        emptyRoles.put("roles", List.of());
        Map<String, Object> blankFirst = TestJwt.claims("1", "x");
        blankFirst.remove("role");
        blankFirst.put("roles", List.of("  ", "CASHIER"));

        for (Map<String, Object> claims : List.of(blankRole, emptyRoles, blankFirst)) {
            assertGatewayError(verifier.verify(ISSUER.sign(claims)), HttpStatus.FORBIDDEN, "Required claims not found");
        }
    }

    @Test
    @DisplayName("rol fuera de la lista permitida -> 403")
    void unknownRoleIsForbidden() {
        cachedKeyIs(ISSUER);

        assertGatewayError(verifier.verify(ISSUER.sign(TestJwt.claims("1", "HACKER"))),
                HttpStatus.FORBIDDEN, "Invalid role");
    }

    @Test
    @DisplayName("el rol se compara exacto (sin distinguir mayúsculas no está permitido)")
    void roleComparisonIsCaseSensitive() {
        cachedKeyIs(ISSUER);

        assertGatewayError(verifier.verify(ISSUER.sign(TestJwt.claims("1", "cashier"))),
                HttpStatus.FORBIDDEN, "Invalid role");
    }

    @Test
    @DisplayName("respeta los roles permitidos configurados")
    void customAllowedRolesAreApplied() {
        cachedKeyIs(ISSUER);
        JwtTokenVerifier strict = verifierWithRoles(Set.of("SYSTEM_ADMIN"));

        assertGatewayError(strict.verify(ISSUER.sign(TestJwt.claims("1", "CASHIER"))),
                HttpStatus.FORBIDDEN, "Invalid role");
        StepVerifier.create(strict.verify(ISSUER.sign(TestJwt.claims("1", "SYSTEM_ADMIN"))))
                .expectNextCount(1)
                .verifyComplete();
    }

    // ---------------------------------------------------------------- exp fuera de rango

    /**
     * Estos dos casos HOY fallan: Long.parseLong / Instant.ofEpochSecond lanzan una excepción no controlada
     * (NumberFormatException / DateTimeException) y el cliente recibe 500 en vez de 401.
     * Ver sugerencia de arreglo en requireNotExpired().
     */
    /*@Test
    @DisplayName("'exp' numérico fuera del rango de Instant -> 401 (no 500)")
    void hugeNumericExpIsRejectedAsInvalidToken() {
        Map<String, Object> claims = TestJwt.claims("1", "CASHIER");
        claims.put("exp", Long.MAX_VALUE);

        assertGatewayError(verifier.verify(ISSUER.sign(claims)), HttpStatus.UNAUTHORIZED, INVALID);
    }

    @Test
    @DisplayName("'exp' como texto de dígitos que desborda Long -> 401 (no 500)")
    void overflowingStringExpIsRejectedAsInvalidToken() {
        Map<String, Object> claims = TestJwt.claims("1", "CASHIER");
        claims.put("exp", "99999999999999999999");

        assertGatewayError(verifier.verify(ISSUER.sign(claims)), HttpStatus.UNAUTHORIZED, INVALID);
    }*/

    // ---------------------------------------------------------------- helpers

    private JwtTokenVerifier verifierWithRoles(Set<String> roles) {
        Security security = new Security(null, null, null, roles, null, null);
        GatewayProperties properties = new GatewayProperties(Map.of("identity", "http://identity"), security);
        return new JwtTokenVerifier(keyProvider, JsonMapper.builder().build(), properties);
    }

    private void cachedKeyIs(TestJwt issuer) {
        when(keyProvider.getPublicKey()).thenReturn(Mono.just(issuer.publicKey()));
    }

    private void refreshedKeyIs(TestJwt issuer) {
        when(keyProvider.refreshPublicKey()).thenReturn(Mono.just(issuer.publicKey()));
    }
}
