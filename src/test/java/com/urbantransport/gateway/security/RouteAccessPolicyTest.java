package com.urbantransport.gateway.security;

import com.urbantransport.gateway.config.GatewayProperties;
import com.urbantransport.gateway.config.GatewayProperties.PublicRoute;
import com.urbantransport.gateway.config.GatewayProperties.Security;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpMethod;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class RouteAccessPolicyTest {

    private final RouteAccessPolicy policy = new RouteAccessPolicy(new GatewayProperties(
            Map.of("identity", "http://identity"),
            new Security(null, null, null, null,
                    List.of(
                            new PublicRoute("POST", "/api/identity/auth/login"),
                            new PublicRoute("get", "/api/ticketing/trips/*/seats"),
                            new PublicRoute("*", "/docs/**")),
                    null)));

    // ---------------------------------------------------------------- isPublic

    @Test
    @DisplayName("ruta pública con el método configurado")
    void publicRouteWithMatchingMethod() {
        assertThat(policy.isPublic(HttpMethod.POST, "/api/identity/auth/login")).isTrue();
    }

    @Test
    @DisplayName("la misma ruta con otro método NO es pública")
    void publicRouteWithDifferentMethodIsNotPublic() {
        assertThat(policy.isPublic(HttpMethod.GET, "/api/identity/auth/login")).isFalse();
        assertThat(policy.isPublic(HttpMethod.DELETE, "/api/identity/auth/login")).isFalse();
    }

    @Test
    @DisplayName("el método configurado se compara sin distinguir mayúsculas")
    void methodComparisonIsCaseInsensitive() {
        assertThat(policy.isPublic(HttpMethod.GET, "/api/ticketing/trips/10/seats")).isTrue();
    }

    @Test
    @DisplayName("'*' como método acepta cualquier método")
    void wildcardMethodMatchesAnyMethod() {
        assertThat(policy.isPublic(HttpMethod.GET, "/docs/identity/v3/api-docs")).isTrue();
        assertThat(policy.isPublic(HttpMethod.POST, "/docs/identity/v3/api-docs")).isTrue();
    }

    @Test
    @DisplayName("'*' en la ruta cubre un solo segmento")
    void singleWildcardCoversExactlyOneSegment() {
        assertThat(policy.isPublic(HttpMethod.GET, "/api/ticketing/trips/10/seats")).isTrue();
        assertThat(policy.isPublic(HttpMethod.GET, "/api/ticketing/trips/seats")).isFalse();
        assertThat(policy.isPublic(HttpMethod.GET, "/api/ticketing/trips/10/20/seats")).isFalse();
    }

    @Test
    @DisplayName("una ruta que solo comparte prefijo con una pública no es pública")
    void prefixOfPublicRouteIsNotPublic() {
        assertThat(policy.isPublic(HttpMethod.POST, "/api/identity/auth/login/extra")).isFalse();
        assertThat(policy.isPublic(HttpMethod.POST, "/api/identity/auth")).isFalse();
        assertThat(policy.isPublic(HttpMethod.GET, "/api/fleet/vehicles")).isFalse();
    }

    @Test
    @DisplayName("sin rutas públicas configuradas nada es público")
    void nothingIsPublicWithoutConfiguration() {
        RouteAccessPolicy empty = new RouteAccessPolicy(new GatewayProperties(null, null));

        assertThat(empty.isPublic(HttpMethod.GET, "/anything")).isFalse();
    }

    // --------------------------------------------------------------- isBlocked

    @ParameterizedTest
    @ValueSource(strings = {
            "/api/fleet/internal/vehicles",
            "/api/identity/internal/users/1/roles",
            "/api/fleet/internal"
    })
    @DisplayName("rutas /api/*/internal/** están bloqueadas")
    void internalPathsAreBlocked(String path) {
        assertThat(policy.isBlocked(path)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/api/fleet/vehicles",
            "/api/internal",
            "/api/fleet/internals",
            "/api/fleet/v1/internal/x",
            "/internal/api/fleet"
    })
    @DisplayName("rutas normales o parecidas no se bloquean")
    void regularPathsAreNotBlocked(String path) {
        assertThat(policy.isBlocked(path)).isFalse();
    }

    @Test
    @DisplayName("usa los patrones bloqueados configurados en lugar del default")
    void customBlockedPatternsReplaceTheDefault() {
        RouteAccessPolicy custom = new RouteAccessPolicy(new GatewayProperties(null,
                new Security(null, null, null, null, null, List.of("/admin/**"))));

        assertThat(custom.isBlocked("/admin/panel")).isTrue();
        assertThat(custom.isBlocked("/api/fleet/internal/x")).isFalse();
    }

    // ------------------------------------------------------------- isSuspicious

    @ParameterizedTest
    @ValueSource(strings = {
            "/api//fleet",
            "/api/fleet//vehicles",
            "/api\\fleet",
            "/api/fleet\\..\\internal",
            "/api/../internal",
            "/api/fleet/../internal/x",
            "/api/./fleet",
            "/api/%2e%2e/internal",
            "/api/%2E%2E/internal",
            "/api/%2e/fleet",
            "/api/fleet%2Finternal",
            "/api/fleet%2finternal/x",
            "/api/fleet%5Cinternal"
    })
    @DisplayName("rutas que intentan esquivar los patrones se marcan como sospechosas")
    void bypassAttemptsAreSuspicious(String path) {
        assertThat(policy.isSuspicious(path)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/",
            "/api/fleet/vehicles",
            "/api/fleet/vehicles/",
            "/api/ticketing/trips/abc-123/seats",
            "/api/fleet/v1.0/items",
            "/api/fleet/file..name",
            "/api/fleet/vehicles/%C3%A1rbol",
            "/api/fleet/search/a%20b"
    })
    @DisplayName("rutas legítimas no se marcan como sospechosas")
    void legitimatePathsAreNotSuspicious(String path) {
        assertThat(policy.isSuspicious(path)).isFalse();
    }
}
