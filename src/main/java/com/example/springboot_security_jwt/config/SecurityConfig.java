package com.example.springboot_security_jwt.config;

import com.example.springboot_security_jwt.jwt.JwtAccessDeniedHandler;
import com.example.springboot_security_jwt.jwt.JwtAuthenticationEntryPoint;
import com.example.springboot_security_jwt.jwt.JwtFilter;
import com.example.springboot_security_jwt.jwt.TokenProvider;
import lombok.AllArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@AllArgsConstructor
public class SecurityConfig {
    private final TokenProvider tokenProvider;
    private final CorsConfigurationSource corsConfigurationSource;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        JwtFilter jwtFilter = new JwtFilter(tokenProvider);

        http
            // CORS 설정 추가
            .cors(cors -> cors.configurationSource(corsConfigurationSource))

            // CSRF 비활성화 (token을 사용하는 방식이기 때문에)
            .csrf(AbstractHttpConfigurer::disable)

            // 예외 처리
            .exceptionHandling(exceptionHandling -> exceptionHandling
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)
            )

            // 세션을 사용하지 않기 때문에 세션 관리를 STATELESS로 설정
            .sessionManagement(sessionManagement -> sessionManagement
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )

            // HTTP 헤더 설정 / H2 콘솔을 위해 Frame Options 비활성화
            .headers(headerConfig -> headerConfig
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin)
            )

            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/api/authenticate", "/api/signup").permitAll()
                .requestMatchers(PathRequest.toH2Console()).permitAll()
                .anyRequest().authenticated()
            )

            // JwtSecurityConfig를 적용하여 JwtFilter 추가
            //.with(new JwtSecurityConfig(tokenProvider), customizer -> {});

            // JwtFilter를 UsernamePasswordAuthenticationFilter 전에 추가
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}