package com.sacareers.gateway.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class CustomJwtAuthenticationConverter implements Converter<Jwt, Mono<AbstractAuthenticationToken>>
    {
        private static Collection<? extends GrantedAuthority> extractResourceRoles(final Jwt jwt)
        {
            Map<String, Object> realmAccess = jwt.getClaim("realm_access");
            Collection<String> roles;
            if (realmAccess != null && (roles = (Collection<String>) realmAccess.get("roles")) != null)
                return roles.stream()
                        .map(x -> new SimpleGrantedAuthority("ROLE_" + x))
                        .collect(Collectors.toSet());
            return Collections.emptySet();
        }

        private final JwtGrantedAuthoritiesConverter defaultGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

        @Override
        public Mono<AbstractAuthenticationToken> convert(final Jwt source)
        {
            Collection<GrantedAuthority> authorities = Stream.concat(defaultGrantedAuthoritiesConverter
                            .convert(source)
                            .stream(), extractResourceRoles(source).stream()).collect(Collectors.toSet());
            return Mono.just(new JwtAuthenticationToken(source, authorities));
        }
    }