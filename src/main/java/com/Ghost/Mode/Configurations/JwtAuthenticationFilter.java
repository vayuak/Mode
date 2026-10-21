package com.Ghost.Mode.Configurations;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import java.nio.charset.StandardCharsets;

@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Value("${ghost.shield.jwt-secret}")
    private String secretKey;

    private final ReactiveStringRedisTemplate reactiveRedisTemplate;

    public JwtAuthenticationFilter(ReactiveStringRedisTemplate reactiveRedisTemplate) {
        super(Config.class);
        this.reactiveRedisTemplate = reactiveRedisTemplate;
    }

    public static class Config {}

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return onError(exchange, HttpStatus.UNAUTHORIZED);
            }

            try {
                String token = authHeader.substring(7);

                Claims claims = Jwts.parser()
                        .verifyWith(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8)))
                        .build()
                        .parseSignedClaims(token)
                        .getPayload();

                String identity;
                if (claims.get("username") != null && !claims.get("username").toString().trim().isEmpty()) {
                    identity = claims.get("username").toString().trim().toLowerCase();
                } else if (claims.getSubject() != null && !claims.getSubject().trim().isEmpty() && !claims.getSubject().startsWith("user_")) {
                    identity = claims.getSubject().trim().toLowerCase();
                } else {
                    identity = claims.get("userId") != null ? claims.get("userId").toString() : claims.getSubject();
                }

                final String cleanIdentity = identity;
                return reactiveRedisTemplate.hasKey("banned:" + cleanIdentity)
                        .flatMap(isBanned -> {

                            // If the user is banned...
                            if (Boolean.TRUE.equals(isBanned)) {
                                HttpMethod method = exchange.getRequest().getMethod();

                                // ...and they try to POST, PUT, DELETE, or PATCH (Write actions)
                                if (method != null && (method.matches("POST") || method.matches("PUT") || method.matches("DELETE") || method.matches("PATCH"))) {

                                    log.error("⛔ [SHADOWBAN MUTE] Banned user @{} attempted a write action ({}). Dropped with 403 Forbidden.", cleanIdentity, method);

                                    // 403 Forbidden means "You are authenticated, but you are not allowed to do this."
                                    return onError(exchange, HttpStatus.FORBIDDEN);
                                }
                                // If it's just a GET request (reading the feed), we let it pass!
                            }

                            // Inject the validated User-Id header and pass it to the Microservices
                            ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                                    .header("X-User-Id", cleanIdentity)
                                    .build();

                            return chain.filter(exchange.mutate().request(mutatedRequest).build());
                        });

            } catch (Exception e) {
                log.error("Gateway guard validation failed: {}", e.getMessage());
                return onError(exchange, HttpStatus.UNAUTHORIZED);
            }
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus status) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        return response.setComplete();
    }
}