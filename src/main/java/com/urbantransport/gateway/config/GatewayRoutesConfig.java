package com.urbantransport.gateway.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Genera las rutas a partir de {@code gateway.services.*}. Agregar un microservicio nuevo
 * solo requiere una línea en application.properties.
 *
 * <ul>
 *   <li>{@code /api/{servicio}/**} se reenvía al servicio quitando los dos primeros segmentos
 *       ({@code /api/identity/auth/login} llega como {@code /auth/login}).</li>
 *   <li>{@code /docs/{servicio}/v3/api-docs} expone el OpenAPI de cada servicio para el Swagger agregado.</li>
 * </ul>
 *
 * La autenticación no vive aquí: la aplica el filtro global {@code JwtAuthenticationFilter}.
 */
@Configuration
public class GatewayRoutesConfig {

    @Bean
    public RouteLocator routeLocator(RouteLocatorBuilder builder, GatewayProperties properties) {
        RouteLocatorBuilder.Builder routes = builder.routes();

        properties.services().forEach((name, uri) -> {
            routes.route("api-" + name, route -> route
                    .path("/api/" + name + "/**")
                    .filters(filters -> filters.stripPrefix(2))
                    .uri(uri));

            routes.route("docs-" + name, route -> route
                    .path("/docs/" + name + "/v3/api-docs")
                    .filters(filters -> filters.rewritePath("/docs/" + name + "/(?<segment>.*)", "/${segment}"))
                    .uri(uri));
        });

        return routes.build();
    }
}
