package com.urbantransport.gateway.security;

import com.urbantransport.gateway.config.GatewayProperties;
import com.urbantransport.gateway.config.GatewayProperties.Security;
import com.urbantransport.gateway.support.TestJwt;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import tools.jackson.databind.json.JsonMapper;

import java.net.ConnectException;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.IntFunction;

import static com.urbantransport.gateway.support.GatewayAssertions.assertGatewayError;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Pruebas unitarias del provider: el WebClient usa un ExchangeFunction falso,
 * así que no se abre ningún puerto ni se llama a un identity real.
 */
class PublicKeyProviderTest {

    private static final TestJwt KEY_A = new TestJwt();
    private static final TestJwt KEY_B = new TestJwt();
    private static final String IDENTITY = "http://identity.test";

    private final JsonMapper mapper = JsonMapper.builder().build();
    private final AtomicInteger calls = new AtomicInteger();
    private final List<URI> requestedUris = new CopyOnWriteArrayList<>();

    /** Respuesta de "identity" según el número de llamada (1, 2, 3...). */
    private IntFunction<Mono<ClientResponse>> identity = call -> ok(KEY_A.publicKeyPem());

    // ---------------------------------------------------------------- lectura de la llave

    @Test
    @DisplayName("lee la llave cuando identity responde PEM en texto plano")
    void readsPlainPem() {
        PublicKeyProvider provider = provider(null);

        StepVerifier.create(provider.getPublicKey())
                .assertNext(key -> assertThat(key.getEncoded()).isEqualTo(KEY_A.publicKey().getEncoded()))
                .verifyComplete();
        assertThat(requestedUris).singleElement().satisfies(uri ->
                assertThat(uri.toString()).isEqualTo(IDENTITY + "/auth/public-key"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"publicKey", "public_key", "key"})
    @DisplayName("lee la llave cuando viene dentro de un JSON (publicKey, public_key o key)")
    void readsPemInsideJson(String field) {
        identity = call -> ok(mapper.writeValueAsString(Map.of(field, KEY_A.publicKeyPem())));

        StepVerifier.create(provider(null).getPublicKey())
                .assertNext(key -> assertThat(key.getEncoded()).isEqualTo(KEY_A.publicKey().getEncoded()))
                .verifyComplete();
    }

    @Test
    @DisplayName("usa el endpoint configurado")
    void usesConfiguredEndpoint() {
        PublicKeyProvider provider = provider(new Security("/keys/rsa", null, null, null, null, null));

        provider.getPublicKey().block();

        assertThat(requestedUris).singleElement().satisfies(uri ->
                assertThat(uri.toString()).isEqualTo(IDENTITY + "/keys/rsa"));
    }

    // ---------------------------------------------------------------- caché

    @Test
    @DisplayName("la llave se guarda en caché: varias lecturas, una sola llamada a identity")
    void keyIsCached() {
        PublicKeyProvider provider = provider(null);

        provider.getPublicKey().block();
        provider.getPublicKey().block();
        provider.getPublicKey().block();

        assertThat(calls).hasValue(1);
    }

    @Test
    @DisplayName("lecturas concurrentes comparten una sola llamada")
    void concurrentReadsShareOneCall() {
        PublicKeyProvider provider = provider(null);

        Mono.zip(provider.getPublicKey(), provider.getPublicKey(), provider.getPublicKey()).block();

        assertThat(calls).hasValue(1);
    }

    @Test
    @DisplayName("los errores no se cachean: el siguiente intento vuelve a consultar identity")
    void errorsAreNotCached() {
        identity = call -> call == 1 ? status(HttpStatus.INTERNAL_SERVER_ERROR) : ok(KEY_A.publicKeyPem());
        PublicKeyProvider provider = provider(null);

        assertGatewayError(provider.getPublicKey(), HttpStatus.SERVICE_UNAVAILABLE, "Authentication service unavailable");
        StepVerifier.create(provider.getPublicKey()).expectNextCount(1).verifyComplete();

        assertThat(calls).hasValue(2);
    }

    // ---------------------------------------------------------------- refresh

    @Test
    @DisplayName("refresh trae la llave nueva cuando identity la rotó")
    void refreshPicksUpRotatedKey() {
        identity = call -> call == 1 ? ok(KEY_A.publicKeyPem()) : ok(KEY_B.publicKeyPem());
        PublicKeyProvider provider = provider(null);

        assertThat(provider.getPublicKey().block().getEncoded()).isEqualTo(KEY_A.publicKey().getEncoded());
        assertThat(provider.refreshPublicKey().block().getEncoded()).isEqualTo(KEY_B.publicKey().getEncoded());
        // Y la llave nueva queda en caché
        assertThat(provider.getPublicKey().block().getEncoded()).isEqualTo(KEY_B.publicKey().getEncoded());
        assertThat(calls).hasValue(2);
    }

    @Test
    @DisplayName("refresh respeta el intervalo mínimo: tokens falsos no generan una llamada a identity cada vez")
    void refreshRespectsMinimumInterval() {
        PublicKeyProvider provider = provider(new Security(null, null, Duration.ofMinutes(10), null, null, null));

        provider.getPublicKey().block();          // 1 llamada (carga inicial)
        provider.refreshPublicKey().block();      // 2: primera recarga permitida
        provider.refreshPublicKey().block();      // sigue dentro del intervalo: reutiliza
        provider.refreshPublicKey().block();

        assertThat(calls).hasValue(2);
    }

    @Test
    @DisplayName("con intervalo cero, cada refresh vuelve a consultar identity")
    void refreshWithZeroIntervalAlwaysFetches() {
        PublicKeyProvider provider = provider(new Security(null, null, Duration.ZERO, null, null, null));

        provider.refreshPublicKey().block();
        provider.refreshPublicKey().block();
        provider.refreshPublicKey().block();

        assertThat(calls).hasValue(3);
    }

    // ---------------------------------------------------------------- errores de identity

    @ParameterizedTest
    @ValueSource(ints = {400, 401, 404, 500, 503})
    @DisplayName("identity responde error HTTP -> 503 genérico")
    void httpErrorsBecomeServiceUnavailable(int code) {
        identity = call -> status(HttpStatus.valueOf(code));

        assertGatewayError(provider(null).getPublicKey(), HttpStatus.SERVICE_UNAVAILABLE,
                "Authentication service unavailable");
    }

    @Test
    @DisplayName("identity no acepta conexiones -> 503")
    void connectionFailureBecomesServiceUnavailable() {
        identity = call -> Mono.error(new ConnectException("refused"));

        assertGatewayError(provider(null).getPublicKey(), HttpStatus.SERVICE_UNAVAILABLE,
                "Authentication service unavailable");
    }

    @Test
    @DisplayName("respuesta vacía -> 502")
    void emptyBodyIsBadGateway() {
        identity = call -> status(HttpStatus.OK);

        assertGatewayError(provider(null).getPublicKey(), HttpStatus.BAD_GATEWAY,
                "Invalid public key received from identity-service");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "esto no es una llave",
            "{\"otraCosa\":\"valor\"}",
            "{\"publicKey\":\"   \"}",
            "{\"publicKey\":123}",
            "[]",
            "-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----",
            "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"
    })
    @DisplayName("cuerpo que no contiene una llave RSA válida -> 502")
    void invalidKeyMaterialIsBadGateway(String body) {
        identity = call -> ok(body);

        assertGatewayError(provider(null).getPublicKey(), HttpStatus.BAD_GATEWAY,
                "Invalid public key received from identity-service");
    }

    // ---------------------------------------------------------------- configuración

    @Test
    @DisplayName("sin gateway.services.identity el provider no arranca")
    void failsFastWithoutIdentityService() {
        assertThatThrownBy(() -> create(Map.of("fleet", "http://fleet"), null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("gateway.services.identity");
        assertThatThrownBy(() -> create(Map.of("identity", "  "), null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("gateway.services.identity");
    }

    // ---------------------------------------------------------------- helpers

    private PublicKeyProvider provider(Security security) {
        return create(Map.of("identity", IDENTITY), security);
    }

    private PublicKeyProvider create(Map<String, String> services, Security security) {
        WebClient.Builder builder = WebClient.builder().exchangeFunction(request -> {
            int call = calls.incrementAndGet();
            requestedUris.add(request.url());
            return identity.apply(call);
        });
        return new PublicKeyProvider(builder, mapper, new GatewayProperties(services, security));
    }

    private static Mono<ClientResponse> ok(String body) {
        return Mono.just(ClientResponse.create(HttpStatus.OK)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_PLAIN_VALUE)
                .body(body)
                .build());
    }

    private static Mono<ClientResponse> status(HttpStatus status) {
        return Mono.just(ClientResponse.create(status).build());
    }
}
