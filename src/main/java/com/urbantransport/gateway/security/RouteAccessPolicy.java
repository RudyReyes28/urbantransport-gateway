package com.urbantransport.gateway.security;

import com.urbantransport.gateway.config.GatewayProperties;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.PathContainer;
import org.springframework.stereotype.Component;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

import java.util.List;

/**
 * Decide qué hacer con una ruta entrante según {@code gateway.security.*}:
 * rutas públicas (sin token), rutas bloqueadas (nunca se exponen) y rutas sospechosas.
 */
@Component
public class RouteAccessPolicy {

    private final List<PublicRule> publicRules;
    private final List<PathPattern> blockedPatterns;

    public RouteAccessPolicy(GatewayProperties properties) {
        PathPatternParser parser = new PathPatternParser();
        this.publicRules = properties.security().publicRoutes().stream()
                .map(route -> new PublicRule(route.method(), parser.parse(route.path())))
                .toList();
        this.blockedPatterns = properties.security().blockedPaths().stream()
                .map(parser::parse)
                .toList();
    }

    public boolean isPublic(HttpMethod method, String path) {
        PathContainer container = PathContainer.parsePath(path);
        return publicRules.stream().anyMatch(rule -> rule.matches(method, container));
    }

    public boolean isBlocked(String path) {
        PathContainer container = PathContainer.parsePath(path);
        return blockedPatterns.stream().anyMatch(pattern -> pattern.matches(container));
    }

    /**
     * Detecta rutas que intentan esquivar los patrones de arriba: segmentos vacíos ({@code //}),
     * segmentos {@code .} o {@code ..} (también codificados) y barras codificadas dentro de un segmento.
     * Un servicio detrás (por ejemplo Tomcat) normalizaría esas rutas y podría exponer un endpoint bloqueado.
     */
    public boolean isSuspicious(String path) {
        if (path.contains("//") || path.contains("\\")) {
            return true;
        }
        return PathContainer.parsePath(path).elements().stream()
                .filter(PathContainer.PathSegment.class::isInstance)
                .map(PathContainer.PathSegment.class::cast)
                .map(PathContainer.PathSegment::valueToMatch)
                .anyMatch(segment -> segment.equals(".") || segment.equals("..")
                        || segment.contains("/") || segment.contains("\\"));
    }

    private record PublicRule(String method, PathPattern pattern) {
        boolean matches(HttpMethod requestMethod, PathContainer path) {
            boolean methodMatches = "*".equals(method) || method.equalsIgnoreCase(requestMethod.name());
            return methodMatches && pattern.matches(path);
        }
    }
}
