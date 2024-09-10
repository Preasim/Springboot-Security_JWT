package com.example.springboot_security_jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
public class CorsConfig {
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        //모든 출처에 대해 스크립트 기반의 HTTP 통신 허용
        configuration.setAllowedOrigins(Arrays.asList("*"));
        //HTTP Method에 대한 HTTP 통신 허용
        configuration.setAllowedMethods(Arrays.asList("GET","POST","PATCH","DELETE"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        //모든 URL에 앞서 구성한 CORS 정책을 적용
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
