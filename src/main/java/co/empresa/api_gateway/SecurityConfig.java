package co.empresa.api_gateway;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import reactor.core.publisher.Flux;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

/**
 * Seguridad del API Gateway.
 *
 * El Gateway valida el JWT una sola vez aquí — los microservicios
 * confían en que el Gateway ya lo verificó.
 *
 * Rutas públicas (sin JWT):
 *   - GET  /api/v1/events, /api/v1/events/search, /api/v1/events/{id}
 *   - POST /auth/login, /auth/register, /auth/refresh
 *   - POST /api/payments/webhook/**  (MercadoPago no manda JWT)
 *   - GET  /actuator/health
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public ReactiveJwtDecoder jwtDecoder() {
        return NimbusReactiveJwtDecoder.withJwkSetUri(
                "http://keycloak:8080/realms/viva-eventos/protocol/openid-connect/certs"
        ).build();
    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
                .csrf(csrf -> csrf.disable())
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeExchange(exchange -> exchange

                        // ── OPTIONS siempre libre para preflight ──────────────────────
                        .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // ── Health check ──────────────────────────────────────────────
                        .pathMatchers("/actuator/health").permitAll()

                        // ── Auth: login, register, refresh — sin JWT ──────────────────
                        .pathMatchers(HttpMethod.POST, "/auth/login").permitAll()
                        .pathMatchers(HttpMethod.POST, "/auth/register").permitAll()
                        .pathMatchers(HttpMethod.POST, "/auth/refresh").permitAll()

                        // ── Catálogo público de eventos ───────────────────────────────
                        .pathMatchers(HttpMethod.GET, "/api/v1/events").permitAll()
                        .pathMatchers(HttpMethod.GET, "/api/v1/events/search").permitAll()
                        .pathMatchers(HttpMethod.GET, "/api/v1/events/{id}").permitAll()

                        // ── Webhook de MercadoPago — sin JWT ──────────────────────────
                        .pathMatchers("/api/payments/webhook/**").permitAll()

                        // ── Todo lo demás requiere JWT válido ─────────────────────────
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                );

        return http.build();
    }

    /**
     * Configuración CORS centralizada.
     * Se aplica antes de que Spring Security evalúe las reglas de autorización,
     * garantizando que los preflights OPTIONS siempre reciban los headers correctos.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(List.of("*"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    /**
     * Mismo patrón que ticket-service y event-service:
     * extrae roles de realm_access.roles y agrega ROLE_ si falta.
     */
    @Bean
    public ReactiveJwtAuthenticationConverter jwtAuthenticationConverter() {
        ReactiveJwtAuthenticationConverter converter = new ReactiveJwtAuthenticationConverter();

        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Map<String, Object> realmAccess = jwt.getClaim("realm_access");
            if (realmAccess == null || !realmAccess.containsKey("roles")) {
                return Flux.empty();
            }

            @SuppressWarnings("unchecked")
            Collection<String> roles = (Collection<String>) realmAccess.get("roles");

            return Flux.fromIterable(roles)
                    .map(role -> new SimpleGrantedAuthority(
                            role.startsWith("ROLE_") ? role : "ROLE_" + role));
        });

        return converter;
    }
}