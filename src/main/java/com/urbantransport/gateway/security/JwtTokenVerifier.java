package com.urbantransport.gateway.security;

import com.urbantransport.gateway.config.GatewayProperties;
import com.urbantransport.gateway.constants.GatewayConstants;
import com.urbantransport.gateway.exception.GatewayException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import tools.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Verifica un JWT RS256 y devuelve la identidad del usuario.
 *
 * <p>Orden de validación: formato, algoritmo declarado, expiración, firma (con una recarga de la
 * llave si falla, por si identity la rotó) y por último los claims y el rol.
 * El token se decodifica una sola vez.</p>
 *
 * <p>Errores: 401 para token malformado, vencido o con firma inválida; 403 para token válido sin
 * claims requeridos o con un rol no permitido.</p>
 */
@Component
public class JwtTokenVerifier {

    private static final Logger log = LoggerFactory.getLogger(JwtTokenVerifier.class);
    private static final String INVALID_TOKEN = "Invalid or expired token";

    private final PublicKeyProvider publicKeyProvider;
    private final JsonMapper jsonMapper;
    private final Set<String> allowedRoles;

    public JwtTokenVerifier(PublicKeyProvider publicKeyProvider, JsonMapper jsonMapper, GatewayProperties properties) {
        this.publicKeyProvider = publicKeyProvider;
        this.jsonMapper = jsonMapper;
        this.allowedRoles = properties.security().allowedRoles();
    }

    public Mono<AuthenticatedUser> verify(String token) {
        return Mono.defer(() -> {
            ParsedJwt jwt = parse(token);
            requireRs256(jwt);
            requireNotExpired(jwt);

            return publicKeyProvider.getPublicKey()
                    .filter(key -> hasValidSignature(jwt, key))
                    .switchIfEmpty(Mono.defer(() -> {
                        log.debug("JWT signature failed with cached key, trying a refreshed key");
                        return publicKeyProvider.refreshPublicKey().filter(key -> hasValidSignature(jwt, key));
                    }))
                    .switchIfEmpty(Mono.error(() -> new GatewayException(HttpStatus.UNAUTHORIZED, INVALID_TOKEN)))
                    .map(key -> toUser(jwt));
        });
    }

    @SuppressWarnings("unchecked")
    private ParsedJwt parse(String token) {
        String[] sections = token.split("\\.", -1);
        if (sections.length != 3) {
            throw invalidToken();
        }
        try {
            Base64.Decoder decoder = Base64.getUrlDecoder();
            Map<String, Object> header = jsonMapper.readValue(decoder.decode(sections[0]), Map.class);
            Map<String, Object> claims = jsonMapper.readValue(decoder.decode(sections[1]), Map.class);
            byte[] signature = decoder.decode(sections[2]);
            if (header == null || claims == null) {
                throw invalidToken();
            }
            return new ParsedJwt(sections[0] + "." + sections[1], signature, header, claims);
        } catch (GatewayException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            // Base64 inválido (IllegalArgumentException) o JSON inválido (excepción no verificada de Jackson 3)
            throw invalidToken();
        }
    }

    private void requireRs256(ParsedJwt jwt) {
        if (!GatewayConstants.RS256_ALGORITHM.equals(jwt.header().get("alg"))) {
            throw invalidToken();
        }
    }

    private void requireNotExpired(ParsedJwt jwt) {
        Object exp = jwt.claims().get(GatewayConstants.CLAIM_EXP);
        Long epochSeconds = null;
        if (exp instanceof Number number) {
            epochSeconds = number.longValue();
        } else if (exp instanceof String text && text.matches("\\d+")) {
            epochSeconds = Long.parseLong(text);
        }
        if (epochSeconds == null || !Instant.ofEpochSecond(epochSeconds).isAfter(Instant.now())) {
            throw invalidToken();
        }
    }

    private boolean hasValidSignature(ParsedJwt jwt, RSAPublicKey key) {
        try {
            Signature signature = Signature.getInstance(GatewayConstants.SIGNATURE_ALGORITHM);
            signature.initVerify(key);
            signature.update(jwt.signingInput().getBytes(StandardCharsets.UTF_8));
            return signature.verify(jwt.signature());
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            return false;
        }
    }

    private AuthenticatedUser toUser(ParsedJwt jwt) {
        Map<String, Object> claims = jwt.claims();
        String userId = text(claims, GatewayConstants.CLAIM_USER_ID);
        if (userId == null) {
            userId = text(claims, GatewayConstants.CLAIM_SUB);
        }
        String role = text(claims, GatewayConstants.CLAIM_ROLE);
        if (role == null && claims.get(GatewayConstants.CLAIM_ROLES) instanceof List<?> roles && !roles.isEmpty()
                && roles.get(0) instanceof String first && !first.isBlank()) {
            role = first.trim();
        }
        if (userId == null || role == null) {
            throw new GatewayException(HttpStatus.FORBIDDEN, "Required claims not found");
        }
        if (!allowedRoles.contains(role)) {
            throw new GatewayException(HttpStatus.FORBIDDEN, "Invalid role");
        }
        return new AuthenticatedUser(
                userId,
                role,
                text(claims, GatewayConstants.CLAIM_BRANCH_ID),
                text(claims, GatewayConstants.CLAIM_CUSTOMER_ID),
                text(claims, GatewayConstants.CLAIM_NIT)
        );
    }

    /** Lee un claim como texto; acepta números (ids numéricos) y descarta valores vacíos. */
    private String text(Map<String, Object> claims, String name) {
        Object value = claims.get(name);
        if (value instanceof String string) {
            return string.isBlank() ? null : string.trim();
        }
        if (value instanceof Number number) {
            return String.valueOf(number);
        }
        return null;
    }

    private GatewayException invalidToken() {
        return new GatewayException(HttpStatus.UNAUTHORIZED, INVALID_TOKEN);
    }

    private record ParsedJwt(String signingInput, byte[] signature, Map<String, Object> header, Map<String, Object> claims) {
    }
}
