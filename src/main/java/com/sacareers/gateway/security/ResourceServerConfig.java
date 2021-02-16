package com.sacareers.gateway.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.PathResource;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

import java.nio.file.PathMatcher;

@EnableWebFluxSecurity
@Configuration
public class ResourceServerConfig {

    @Autowired
    private CustomJwtAuthenticationConverter customJwtAuthenticationConverter;

    @Bean
    protected SecurityWebFilterChain securitygWebFilterChain(ServerHttpSecurity http) throws Exception {
        http.httpBasic().disable()
                .authorizeExchange()
                .pathMatchers("/actuator/**")
                .permitAll()
                .pathMatchers("/**")
                .authenticated()
                .and()
                .oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(customJwtAuthenticationConverter);

        return http.build();
    }
}
