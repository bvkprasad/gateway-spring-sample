package com.sacareers.gateway.filter;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.sacareers.gateway.exception.GatewayException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

@Slf4j
@Component
public class HeaderModifierFilter implements GlobalFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        log.debug("request header modification started");
        ServerHttpRequest request = exchange.getRequest();
        HttpHeaders headers = request.getHeaders();
        try {
            String token = headers.getFirst("Authorization");
            JWT jwt = JWTParser.parse(token.substring(token.indexOf(" ")));
            JWTClaimsSet jwtClaimSet = jwt.getJWTClaimsSet();
            Map<String, Object> rolesClaim = jwtClaimSet.getJSONObjectClaim("realm_access");
            List<String> rolesList = (List<String>) rolesClaim.get("roles");
            String roles = StringUtils.collectionToCommaDelimitedString(rolesList);
            String username = jwtClaimSet.getStringClaim("user_name");
            request = request.mutate()
                    .headers((httpHeaders) -> {
                            httpHeaders.remove("Authorization");
                            httpHeaders.add("ROLE", roles);
                            httpHeaders.add("USERNAME", username);
                    })
                    .build();
        } catch (Exception e) {
            log.error("error occured in gateway", e);
            throw new GatewayException(e.getMessage());
        }
        log.debug("request header modification ended");
        return chain.filter(exchange.mutate().request(request).build());
    }
}
