package com.urbantransport.gateway.security;

import com.urbantransport.gateway.config.GatewayProperties;
import com.urbantransport.gateway.exception.GatewayException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import tools.jackson.databind.json.JsonMapper;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Obtiene del identity-service la llave pública RS256 con la que se firman los JWT.
 *
 * <ul>
 *   <li>La llave se guarda en caché durante {@code publicKeyTtl}; las peticiones concurrentes
 *       comparten una sola llamada a identity.</li>
 *   <li>Los errores no se cachean: si identity estaba caído, el siguiente intento vuelve a consultarlo.</li>
 *   <li>{@link #refreshPublicKey()} sirve para cuando identity rota su llave, pero respeta un intervalo
 *       mínimo entre recargas para que tokens falsos no generen una petición a identity cada vez.</li>
 * </ul>
 */
@Component
public class PublicKeyProvider {

    private static final Logger log = LoggerFactory.getLogger(PublicKeyProvider.class);
    private static final Duration FETCH_TIMEOUT = Duration.ofSeconds(5);

    private final WebClient webClient;
    private final JsonMapper jsonMapper;
    private final String endpoint;
    private final Duration ttl;
    private final long minRefreshIntervalMillis;

    private final AtomicReference<Mono<RSAPublicKey>> current = new AtomicReference<>();
    private final AtomicLong lastRefreshMillis = new AtomicLong(0);

    public PublicKeyProvider(WebClient.Builder webClientBuilder, JsonMapper jsonMapper, GatewayProperties properties) {
        String identityUrl = properties.services().get("identity");
        if (identityUrl == null || identityUrl.isBlank()) {
            throw new IllegalStateException("gateway.services.identity is required to load the JWT public key");
        }
        this.webClient = webClientBuilder.baseUrl(identityUrl).build();
        this.jsonMapper = jsonMapper;
        this.endpoint = properties.security().publicKeyEndpoint();
        this.ttl = properties.security().publicKeyTtl();
        this.minRefreshIntervalMillis = properties.security().publicKeyMinRefreshInterval().toMillis();
        this.current.set(newCachedFetch());
    }

    public Mono<RSAPublicKey> getPublicKey() {
        return current.get();
    }

    public Mono<RSAPublicKey> refreshPublicKey() {
        long now = System.currentTimeMillis();
        long last = lastRefreshMillis.get();
        if (now - last >= minRefreshIntervalMillis && lastRefreshMillis.compareAndSet(last, now)) {
            log.info("Refreshing JWT public key from identity-service");
            current.set(newCachedFetch());
        }
        return current.get();
    }

    private Mono<RSAPublicKey> newCachedFetch() {
        return fetch().cache(key -> ttl, error -> Duration.ZERO, () -> Duration.ZERO);
    }

    private Mono<RSAPublicKey> fetch() {
        return webClient.get()
                .uri(endpoint)
                .retrieve()
                .bodyToMono(String.class)
                .timeout(FETCH_TIMEOUT)
                .switchIfEmpty(Mono.error(() -> invalidKey()))
                .map(this::extractPem)
                .map(this::parsePublicKey)
                .doOnNext(key -> log.info("JWT public key loaded"))
                .onErrorMap(ex -> !(ex instanceof GatewayException), ex -> {
                    log.warn("Unable to load JWT public key: {}", ex.toString());
                    return new GatewayException(HttpStatus.SERVICE_UNAVAILABLE, "Authentication service unavailable");
                });
    }

    /**
     * Acepta la llave en PEM plano o dentro de un JSON ({@code publicKey}, {@code public_key} o {@code key}).
     * El JSON se lee como Map para no depender de la API de árboles de Jackson, que cambió en Jackson 3.
     */
    private String extractPem(String body) {
        String normalized = body.trim();
        if (normalized.startsWith("-----BEGIN")) {
            return normalized;
        }
        try {
            Map<?, ?> json = jsonMapper.readValue(normalized, Map.class);
            if (json != null) {
                for (String field : new String[]{"publicKey", "public_key", "key"}) {
                    if (json.get(field) instanceof String value && !value.isBlank()) {
                        return value;
                    }
                }
            }
        } catch (RuntimeException exception) {
            throw invalidKey();
        }
        throw invalidKey();
    }

    private RSAPublicKey parsePublicKey(String pem) {
        try {
            String base64 = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s+", "");
            byte[] decoded = Base64.getDecoder().decode(base64);
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
        } catch (Exception exception) {
            throw invalidKey();
        }
    }

    private GatewayException invalidKey() {
        return new GatewayException(HttpStatus.BAD_GATEWAY, "Invalid public key received from identity-service");
    }
}
