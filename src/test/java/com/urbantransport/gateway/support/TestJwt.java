package com.urbantransport.gateway.support;

import tools.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Utilidad de tests: genera un par de llaves RSA y firma JWT RS256 reales,
 * para probar el verificador sin depender del identity-service.
 */
public final class TestJwt {

    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    private final KeyPair keyPair;

    public TestJwt() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            this.keyPair = generator.generateKeyPair();
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException(exception);
        }
    }

    public RSAPublicKey publicKey() {
        return (RSAPublicKey) keyPair.getPublic();
    }

    /** Llave pública en PEM (X.509 / SubjectPublicKeyInfo), como la devuelve identity. */
    public String publicKeyPem() {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                .encodeToString(keyPair.getPublic().getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + base64 + "\n-----END PUBLIC KEY-----";
    }

    public String sign(Map<String, Object> claims) {
        return sign(Map.of("alg", "RS256", "typ", "JWT"), claims);
    }

    public String sign(Map<String, Object> header, Map<String, Object> claims) {
        String signingInput = encode(header) + "." + encode(claims);
        return signingInput + "." + base64Url(rawSignature(signingInput));
    }

    public static String encode(Map<String, Object> json) {
        return base64Url(MAPPER.writeValueAsBytes(json));
    }

    /** Claims válidos por defecto (vence en 1 hora). El mapa es mutable para que cada test lo ajuste. */
    public static Map<String, Object> claims(String userId, String role) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("user_id", userId);
        claims.put("role", role);
        claims.put("exp", Instant.now().getEpochSecond() + 3600);
        return claims;
    }

    private byte[] rawSignature(String signingInput) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(keyPair.getPrivate());
            signature.update(signingInput.getBytes(StandardCharsets.UTF_8));
            return signature.sign();
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
