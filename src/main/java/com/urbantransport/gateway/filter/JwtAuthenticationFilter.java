package com.urbantransport.gateway.filter;

import com.urbantransport.gateway.constants.GatewayConstants;
import com.urbantransport.gateway.exception.GatewayException;
import com.urbantransport.gateway.security.AuthenticatedUser;
import com.urbantransport.gateway.security.JwtTokenVerifier;
import com.urbantransport.gateway.security.RouteAccessPolicy;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Único filtro de autenticación del gateway; reemplaza a {@code JwtAuthFilter} y {@code VerifyJWTFilterFactory}.
 *
 * <ol>
 *   <li>Rechaza rutas sospechosas (400) y rutas bloqueadas como {@code /api/x/internal/**} (404).</li>
 *   <li>Elimina de la petición las cabeceras {@code X-User-*} / {@code X-Branch-Id} / {@code X-Customer-*}
 *       para que un cliente no pueda suplantar identidad, también en rutas públicas.</li>
 *   <li>Deja pasar el preflight CORS y las rutas públicas.</li>
 *   <li>En el resto exige un bearer token válido e inyecta la identidad como cabeceras.</li>
 * </ol>
 *
 * Los errores del servicio destino no se tocan: se propagan tal cual al {@code GatewayErrorHandler}.
 * El header Authorization sigue su camino porque cada microservicio vuelve a validar el JWT.
 */
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private final RouteAccessPolicy accessPolicy;
    private final JwtTokenVerifier tokenVerifier;

    public JwtAuthenticationFilter(RouteAccessPolicy accessPolicy, JwtTokenVerifier tokenVerifier) {
        this.accessPolicy = accessPolicy;
        this.tokenVerifier = tokenVerifier;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();

        if (accessPolicy.isSuspicious(path)) {
            return Mono.error(new GatewayException(HttpStatus.BAD_REQUEST, "Invalid request path"));
        }
        if (accessPolicy.isBlocked(path)) {
            return Mono.error(new GatewayException(HttpStatus.NOT_FOUND, "Route not found"));
        }

        ServerWebExchange clean = exchange.mutate()
                .request(builder -> builder.headers(headers ->
                        GatewayConstants.IDENTITY_HEADERS.forEach(headers::remove)))
                .build();

        if (HttpMethod.OPTIONS.equals(request.getMethod()) || accessPolicy.isPublic(request.getMethod(), path)) {
            return chain.filter(clean);
        }

        String token = bearerToken(request);
        if (token == null) {
            return Mono.error(new GatewayException(HttpStatus.UNAUTHORIZED, "Missing bearer token"));
        }
        return tokenVerifier.verify(token)
                .flatMap(user -> chain.filter(withUserHeaders(clean, user)));
    }

    private String bearerToken(ServerHttpRequest request) {
        String header = request.getHeaders().getFirst(GatewayConstants.AUTHORIZATION_HEADER);
        if (header == null || !header.startsWith(GatewayConstants.BEARER_PREFIX)) {
            return null;
        }
        String token = header.substring(GatewayConstants.BEARER_PREFIX.length()).trim();
        return token.isEmpty() ? null : token;
    }

    private ServerWebExchange withUserHeaders(ServerWebExchange exchange, AuthenticatedUser user) {
        return exchange.mutate()
                .request(builder -> builder.headers(headers -> {
                    headers.set(GatewayConstants.USER_ID_HEADER, user.userId());
                    headers.set(GatewayConstants.USER_ROLE_HEADER, user.role());
                    if (user.branchId() != null) {
                        headers.set(GatewayConstants.BRANCH_ID_HEADER, user.branchId());
                    }
                    if (user.customerId() != null) {
                        headers.set(GatewayConstants.CUSTOMER_ID_HEADER, user.customerId());
                    }
                    if (user.nit() != null) {
                        headers.set(GatewayConstants.CUSTOMER_NIT_HEADER, user.nit());
                    }
                }))
                .build();
    }

    /** Debe ejecutarse antes que los filtros de ruta (StripPrefix) para ver la ruta original /api/... */
    @Override
    public int getOrder() {
        return -100;
    }
}
