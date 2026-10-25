package com.urbantransport.gateway.config;

import com.urbantransport.gateway.config.GatewayProperties.PublicRoute;
import com.urbantransport.gateway.config.GatewayProperties.Security;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GatewayPropertiesTest {

    @Test
    @DisplayName("sin configuración usa servicios vacíos y valores de seguridad por defecto")
    void appliesDefaultsWhenNothingIsConfigured() {
        GatewayProperties properties = new GatewayProperties(null, null);

        assertThat(properties.services()).isEmpty();
        Security security = properties.security();
        assertThat(security.publicKeyEndpoint()).isEqualTo("/auth/public-key");
        assertThat(security.publicKeyTtl()).isEqualTo(Duration.ofHours(1));
        assertThat(security.publicKeyMinRefreshInterval()).isEqualTo(Duration.ofSeconds(30));
        assertThat(security.allowedRoles())
                .containsExactlyInAnyOrder("SYSTEM_ADMIN", "BRANCH_ADMIN", "CASHIER", "DRIVER", "CUSTOMER");
        assertThat(security.publicRoutes()).isEmpty();
        assertThat(security.blockedPaths()).containsExactly("/api/*/internal/**");
    }

    @Test
    @DisplayName("respeta los valores configurados")
    void keepsConfiguredValues() {
        Security security = new Security(
                "/keys/rsa",
                Duration.ofMinutes(5),
                Duration.ofSeconds(10),
                Set.of("ADMIN"),
                List.of(new PublicRoute("GET", "/api/x/**")),
                List.of("/api/*/secret/**"));

        assertThat(security.publicKeyEndpoint()).isEqualTo("/keys/rsa");
        assertThat(security.publicKeyTtl()).isEqualTo(Duration.ofMinutes(5));
        assertThat(security.publicKeyMinRefreshInterval()).isEqualTo(Duration.ofSeconds(10));
        assertThat(security.allowedRoles()).containsExactly("ADMIN");
        assertThat(security.publicRoutes()).containsExactly(new PublicRoute("GET", "/api/x/**"));
        assertThat(security.blockedPaths()).containsExactly("/api/*/secret/**");
    }

    @Test
    @DisplayName("endpoint en blanco y roles vacíos vuelven a los valores por defecto")
    void blankEndpointAndEmptyRolesFallBackToDefaults() {
        Security security = new Security("   ", null, null, Set.of(), null, null);

        assertThat(security.publicKeyEndpoint()).isEqualTo("/auth/public-key");
        assertThat(security.allowedRoles()).contains("SYSTEM_ADMIN", "CUSTOMER");
    }

    @Test
    @DisplayName("una lista de bloqueados vacía explícita se respeta (no se reemplaza por el default)")
    void explicitEmptyBlockedPathsAreKept() {
        Security security = new Security(null, null, null, null, null, List.of());

        assertThat(security.blockedPaths()).isEmpty();
    }

    @Test
    @DisplayName("los servicios se copian: cambios posteriores al mapa original no afectan, y el resultado es inmutable")
    void servicesAreDefensivelyCopied() {
        Map<String, String> original = new HashMap<>();
        original.put("identity", "http://identity");
        GatewayProperties properties = new GatewayProperties(original, null);

        original.put("fleet", "http://fleet");

        assertThat(properties.services()).containsOnlyKeys("identity");
        assertThatThrownBy(() -> properties.services().put("x", "y"))
                .isInstanceOf(UnsupportedOperationException.class);
    }
}
