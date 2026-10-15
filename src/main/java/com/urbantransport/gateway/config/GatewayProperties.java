package com.urbantransport.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Configuración del gateway (prefijo {@code gateway.*}).
 *
 * @param services nombre del servicio -> URL base. Cada entrada genera las rutas
 *                 {@code /api/{nombre}/**} y {@code /docs/{nombre}/v3/api-docs}.
 *                 La clave {@code identity} es obligatoria: de ahí se obtiene la llave pública del JWT.
 * @param security reglas de seguridad del gateway
 */
@ConfigurationProperties(prefix = "gateway")
public record GatewayProperties(Map<String, String> services, Security security) {

    public GatewayProperties {
        services = services == null ? Map.of() : Map.copyOf(services);
        security = security == null ? new Security(null, null, null, null, null, null) : security;
    }

    /**
     * @param publicKeyEndpoint          ruta del identity-service que devuelve la llave pública RS256
     * @param publicKeyTtl               cuánto tiempo se conserva la llave en caché
     * @param publicKeyMinRefreshInterval mínimo entre dos recargas forzadas de la llave (evita que tokens
     *                                   inválidos hagan una petición a identity por cada intento)
     * @param allowedRoles               roles aceptados en el claim del JWT
     * @param publicRoutes               rutas que no requieren token
     * @param blockedPaths               patrones que el gateway nunca debe exponer (por ejemplo /internal)
     */
    public record Security(
            String publicKeyEndpoint,
            Duration publicKeyTtl,
            Duration publicKeyMinRefreshInterval,
            Set<String> allowedRoles,
            List<PublicRoute> publicRoutes,
            List<String> blockedPaths
    ) {
        public Security {
            publicKeyEndpoint = publicKeyEndpoint == null || publicKeyEndpoint.isBlank()
                    ? "/auth/public-key" : publicKeyEndpoint;
            publicKeyTtl = publicKeyTtl == null ? Duration.ofHours(1) : publicKeyTtl;
            publicKeyMinRefreshInterval = publicKeyMinRefreshInterval == null
                    ? Duration.ofSeconds(30) : publicKeyMinRefreshInterval;
            allowedRoles = allowedRoles == null || allowedRoles.isEmpty()
                    ? Set.of("SYSTEM_ADMIN", "BRANCH_ADMIN", "CASHIER", "DRIVER", "CUSTOMER")
                    : Set.copyOf(allowedRoles);
            publicRoutes = publicRoutes == null ? List.of() : List.copyOf(publicRoutes);
            blockedPaths = blockedPaths == null ? List.of("/api/*/internal/**") : List.copyOf(blockedPaths);
        }
    }

    /**
     * @param method método HTTP, o {@code *} para cualquiera
     * @param path   patrón de ruta (sintaxis PathPattern de Spring: {@code *}, {@code **})
     */
    public record PublicRoute(String method, String path) {
    }
}
