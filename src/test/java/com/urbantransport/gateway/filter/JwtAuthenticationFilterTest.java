package com.urbantransport.gateway.filter;

import com.urbantransport.gateway.config.GatewayProperties;
import com.urbantransport.gateway.config.GatewayProperties.PublicRoute;
import com.urbantransport.gateway.config.GatewayProperties.Security;
import com.urbantransport.gateway.exception.GatewayException;
import com.urbantransport.gateway.security.AuthenticatedUser;
import com.urbantransport.gateway.security.JwtTokenVerifier;
import com.urbantransport.gateway.security.RouteAccessPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.net.URI;
import java.util.List;
import java.util.Map;

import static com.urbantransport.gateway.support.GatewayAssertions.assertGatewayError;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    private static final String PROTECTED = "/api/fleet/vehicles";

    @Mock
    private JwtTokenVerifier tokenVerifier;
    @Mock
    private GatewayFilterChain chain;
    @Captor
    private ArgumentCaptor<ServerWebExchange> forwarded;

    private JwtAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        GatewayProperties properties = new GatewayProperties(
                Map.of("identity", "http://identity"),
                new Security(null, null, null, null,
                        List.of(new PublicRoute("POST", "/api/identity/auth/login"),
                                new PublicRoute("GET", "/api/ticketing/trips/available")),
                        null));
        filter = new JwtAuthenticationFilter(new RouteAccessPolicy(properties), tokenVerifier);
    }

    // ------------------------------------------------------- rutas sospechosas y bloqueadas

    @ParameterizedTest
    @ValueSource(strings = {"/api/fleet/../internal/x", "/api//fleet/vehicles", "/api/%2e%2e/internal"})
    @DisplayName("ruta sospechosa -> 400 y no se llama al resto de la cadena")
    void suspiciousPathIsBadRequest(String path) {
        assertGatewayError(filter.filter(exchange(HttpMethod.GET, path), chain),
                HttpStatus.BAD_REQUEST, "Invalid request path");
        verifyNoInteractions(chain, tokenVerifier);
    }

    @Test
    @DisplayName("ruta /api/*/internal/** -> 404 aunque traiga un token")
    void blockedPathIsNotFound() {
        MockServerWebExchange exchange = exchange(HttpMethod.GET, "/api/fleet/internal/vehicles",
                "Authorization", "Bearer some.valid.token");

        assertGatewayError(filter.filter(exchange, chain), HttpStatus.NOT_FOUND, "Route not found");
        verifyNoInteractions(chain, tokenVerifier);
    }

    // ------------------------------------------------------- rutas públicas y preflight

    @Test
    @DisplayName("ruta pública pasa sin token y sin consultar al verificador")
    void publicRouteSkipsAuthentication() {
        chainPasses();

        StepVerifier.create(filter.filter(exchange(HttpMethod.POST, "/api/identity/auth/login"), chain))
                .verifyComplete();

        verify(chain).filter(any());
        verifyNoInteractions(tokenVerifier);
    }

    /*@Test
    @DisplayName("ruta pública: elimina cabeceras de identidad enviadas por el cliente")
    void publicRouteStripsSpoofedIdentityHeaders() {
        chainPasses();
        MockServerWebExchange exchange = exchange(HttpMethod.POST, "/api/identity/auth/login",
                "X-User-Id", "1", "X-User-Role", "SYSTEM_ADMIN", "X-Branch-Id", "2",
                "X-Customer-Id", "3", "X-Customer-Nit", "CF");

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        HttpHeaders headers = forwardedHeaders();
        assertThat(headers.keySet()).doesNotContain("X-User-Id", "X-User-Role", "X-Branch-Id",
                "X-Customer-Id", "X-Customer-Nit");
    }*/

    @Test
    @DisplayName("la misma ruta pública con otro método sí exige token")
    void publicRouteWithOtherMethodRequiresToken() {
        assertGatewayError(filter.filter(exchange(HttpMethod.GET, "/api/identity/auth/login"), chain),
                HttpStatus.UNAUTHORIZED, "Missing bearer token");
        verifyNoInteractions(chain);
    }

    @Test
    @DisplayName("preflight OPTIONS pasa sin token incluso en rutas protegidas")
    void corsPreflightIsAllowedWithoutToken() {
        chainPasses();

        StepVerifier.create(filter.filter(exchange(HttpMethod.OPTIONS, PROTECTED), chain)).verifyComplete();

        verify(chain).filter(any());
        verifyNoInteractions(tokenVerifier);
    }

    // ------------------------------------------------------- ausencia o forma incorrecta del token

    @Test
    @DisplayName("sin Authorization -> 401")
    void missingAuthorizationHeaderIsUnauthorized() {
        assertGatewayError(filter.filter(exchange(HttpMethod.GET, PROTECTED), chain),
                HttpStatus.UNAUTHORIZED, "Missing bearer token");
        verifyNoInteractions(chain, tokenVerifier);
    }

    @ParameterizedTest
    @ValueSource(strings = {"Basic dXNlcjpwYXNz", "bearer abc.def.ghi", "Bearer", "Bearer ", "Bearer    ", "abc.def.ghi"})
    @DisplayName("Authorization que no es 'Bearer <token>' -> 401")
    void malformedAuthorizationHeaderIsUnauthorized(String header) {
        MockServerWebExchange exchange = exchange(HttpMethod.GET, PROTECTED, "Authorization", header);

        assertGatewayError(filter.filter(exchange, chain), HttpStatus.UNAUTHORIZED, "Missing bearer token");
        verifyNoInteractions(chain, tokenVerifier);
    }

    // ------------------------------------------------------- token válido

    @Test
    @DisplayName("token válido: inyecta identidad y conserva el header Authorization")
    void validTokenInjectsIdentityHeaders() {
        chainPasses();
        when(tokenVerifier.verify("good.token.value"))
                .thenReturn(Mono.just(new AuthenticatedUser("42", "BRANCH_ADMIN", "7", null, null)));

        StepVerifier.create(filter.filter(
                exchange(HttpMethod.GET, PROTECTED, "Authorization", "Bearer good.token.value"), chain))
                .verifyComplete();

        HttpHeaders headers = forwardedHeaders();
        assertThat(headers.getFirst("X-User-Id")).isEqualTo("42");
        assertThat(headers.getFirst("X-User-Role")).isEqualTo("BRANCH_ADMIN");
        assertThat(headers.getFirst("X-Branch-Id")).isEqualTo("7");
        assertThat(headers.getFirst("X-Customer-Id")).isNull();
        assertThat(headers.getFirst("X-Customer-Nit")).isNull();
        assertThat(headers.getFirst("Authorization")).isEqualTo("Bearer good.token.value");
    }

    @Test
    @DisplayName("token de CUSTOMER: inyecta customerId y nit")
    void customerTokenInjectsCustomerHeaders() {
        chainPasses();
        when(tokenVerifier.verify("tok"))
                .thenReturn(Mono.just(new AuthenticatedUser("9", "CUSTOMER", null, "15", "1234567-8")));

        StepVerifier.create(filter.filter(
                exchange(HttpMethod.GET, PROTECTED, "Authorization", "Bearer tok"), chain))
                .verifyComplete();

        HttpHeaders headers = forwardedHeaders();
        assertThat(headers.getFirst("X-User-Role")).isEqualTo("CUSTOMER");
        assertThat(headers.getFirst("X-Customer-Id")).isEqualTo("15");
        assertThat(headers.getFirst("X-Customer-Nit")).isEqualTo("1234567-8");
        assertThat(headers.getFirst("X-Branch-Id")).isNull();
    }

    @Test
    @DisplayName("el valor del token se recorta antes de verificarlo")
    void tokenIsTrimmedBeforeVerification() {
        chainPasses();
        when(tokenVerifier.verify("tok"))
                .thenReturn(Mono.just(new AuthenticatedUser("1", "CASHIER", null, null, null)));

        StepVerifier.create(filter.filter(
                exchange(HttpMethod.GET, PROTECTED, "Authorization", "Bearer   tok  "), chain))
                .verifyComplete();

        verify(tokenVerifier).verify("tok");
    }

    @Test
    @DisplayName("suplantación: las cabeceras X-* del cliente se sobrescriben o se eliminan")
    void spoofedHeadersNeverReachTheService() {
        chainPasses();
        when(tokenVerifier.verify("tok"))
                .thenReturn(Mono.just(new AuthenticatedUser("42", "CASHIER", null, null, null)));
        MockServerWebExchange exchange = exchange(HttpMethod.GET, PROTECTED,
                "Authorization", "Bearer tok",
                "X-User-Id", "999", "X-User-Role", "SYSTEM_ADMIN",
                "X-Branch-Id", "666", "X-Customer-Id", "evil", "X-Customer-Nit", "evil");

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        HttpHeaders headers = forwardedHeaders();
        assertThat(headers.get("X-User-Id")).containsExactly("42");
        assertThat(headers.get("X-User-Role")).containsExactly("CASHIER");
        // El usuario no tiene sucursal/cliente: lo que mandó el cliente no puede colarse.
        assertThat(headers.containsHeader("X-Branch-Id")).isFalse();
        assertThat(headers.containsHeader("X-Customer-Id")).isFalse();
        assertThat(headers.containsHeader("X-Customer-Nit")).isFalse();
    }

    // ------------------------------------------------------- errores del verificador

    @Test
    @DisplayName("si el verificador rechaza el token, el error se propaga y no se llama al servicio")
    void verifierErrorIsPropagated() {
        when(tokenVerifier.verify("bad"))
                .thenReturn(Mono.error(new GatewayException(HttpStatus.UNAUTHORIZED, "Invalid or expired token")));

        assertGatewayError(filter.filter(
                exchange(HttpMethod.GET, PROTECTED, "Authorization", "Bearer bad"), chain),
                HttpStatus.UNAUTHORIZED, "Invalid or expired token");
        verifyNoInteractions(chain);
    }

    @Test
    @DisplayName("el filtro corre antes que StripPrefix (orden -100)")
    void runsBeforeRouteFilters() {
        assertThat(filter.getOrder()).isEqualTo(-100);
    }

    // ------------------------------------------------------- helpers

    private void chainPasses() {
        when(chain.filter(any())).thenReturn(Mono.empty());
    }

    private HttpHeaders forwardedHeaders() {
        verify(chain).filter(forwarded.capture());
        return forwarded.getValue().getRequest().getHeaders();
    }

    /** headers = pares nombre, valor. */
    private static MockServerWebExchange exchange(HttpMethod method, String path, String... headers) {
        MockServerHttpRequest.BaseBuilder<?> builder = MockServerHttpRequest.method(method, URI.create(path));
        for (int i = 0; i < headers.length; i += 2) {
            builder.header(headers[i], headers[i + 1]);
        }
        return MockServerWebExchange.from(builder);
    }
}
