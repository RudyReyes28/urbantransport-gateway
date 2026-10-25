package com.urbantransport.gateway.integration;

import com.urbantransport.gateway.support.TestJwt;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.ServerSocket;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Levanta el gateway real en un puerto aleatorio. Los microservicios son servidores falsos en proceso:
 * sin Docker y con la cobertura de JaCoCo midiéndose en la misma JVM.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@ActiveProfiles("test")
public abstract class AbstractGatewayIT {

    protected static final TestJwt ISSUER = new TestJwt();
    /** Llave que publica "identity" en este momento (los tests de rotación la cambian). */
    protected static final AtomicReference<TestJwt> ACTIVE_KEY = new AtomicReference<>(ISSUER);
    protected static final AtomicInteger PUBLIC_KEY_FETCHES = new AtomicInteger();

    protected static final MockWebServer IDENTITY = new MockWebServer();
    protected static final MockWebServer FLEET = new MockWebServer();
    protected static final MockWebServer FINANCE = new MockWebServer();
    private static final int CLOSED_PORT = findClosedPort();

    static {
        IDENTITY.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
                if ("/auth/public-key".equals(request.getPath())) {
                    PUBLIC_KEY_FETCHES.incrementAndGet();
                    return new MockResponse()
                            .setHeader("Content-Type", "text/plain")
                            .setBody(ACTIVE_KEY.get().publicKeyPem());
                }
                return serviceDispatcher("identity").dispatch(request);
            }
        });
        FLEET.setDispatcher(serviceDispatcher("fleet"));
        FINANCE.setDispatcher(serviceDispatcher("finance"));

        try {
            IDENTITY.start();
            FLEET.start();
            FINANCE.start();
        } catch (IOException exception) {
            throw new UncheckedIOException(exception);
        }
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            for (MockWebServer server : new MockWebServer[]{IDENTITY, FLEET, FINANCE}) {
                try {
                    server.shutdown();
                } catch (IOException ignored) {
                    // cierre al terminar la JVM
                }
            }
        }));
    }

    @DynamicPropertySource
    static void gatewayServices(DynamicPropertyRegistry registry) {
        registry.add("gateway.services.identity", () -> url(IDENTITY));
        registry.add("gateway.services.fleet", () -> url(FLEET));
        registry.add("gateway.services.finance", () -> url(FINANCE));
        registry.add("gateway.services.reporting", () -> "http://localhost:" + CLOSED_PORT);
    }

    @Autowired
    protected WebTestClient client;

    @BeforeEach
    void drainRecordedRequests() throws InterruptedException {
        drain(IDENTITY);
        drain(FLEET);
        drain(FINANCE);
    }

    @AfterEach
    void restoreIdentityKey() {
        ACTIVE_KEY.set(ISSUER);
    }

    // ------------------------------------------------------------------ helpers

    protected static String bearer(Map<String, Object> claims) {
        return "Bearer " + ISSUER.sign(claims);
    }

    /** Petición que llegó al servicio simulado (falla si no llegó ninguna). */
    protected static RecordedRequest requestTo(MockWebServer server) throws InterruptedException {
        RecordedRequest request = server.takeRequest(2, TimeUnit.SECONDS);
        assertThat(request).as("el servicio debía recibir una petición").isNotNull();
        return request;
    }

    protected static void assertNoRequestTo(MockWebServer server) throws InterruptedException {
        assertThat(server.takeRequest(300, TimeUnit.MILLISECONDS))
                .as("el servicio NO debía recibir peticiones").isNull();
    }

    private static void drain(MockWebServer server) throws InterruptedException {
        while (server.takeRequest(50, TimeUnit.MILLISECONDS) != null) {
            // vacía la cola entre tests
        }
    }

    private static String url(MockWebServer server) {
        return "http://localhost:" + server.getPort();
    }

    private static Dispatcher serviceDispatcher(String name) {
        return new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                String path = request.getPath();
                if ("/boom".equals(path)) {
                    return json(500, "{\"error\":\"service-side\"}");
                }
                if ("/slow".equals(path)) {
                    return json(200, "{}").setHeadersDelay(4, TimeUnit.SECONDS);
                }
                return json(200, "{\"service\":\"" + name + "\"}");
            }
        };
    }

    private static MockResponse json(int status, String body) {
        return new MockResponse()
                .setResponseCode(status)
                .setHeader("Content-Type", "application/json")
                .setBody(body);
    }

    private static int findClosedPort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        } catch (IOException exception) {
            throw new UncheckedIOException(exception);
        }
    }
}