package com.example.springboot_security_jwt.jwt;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
// AuthenticationEntryPoint 인터페이스는 인증 실패 시 호출되는 메서드를 제공하며, 인증되지 않은 사용자가 보호된 리소스에 접근할 때 트리거된다.
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    // AuthenticationEntryPoint 인터페이스의 commence() 메서드를 오버라이드하여 정의한다.
    // HttpServletRequest는 요청 객체이다. 인증이 실패한 HTTP 요청의 정보를 포함하고 있다.
    // HttpServletResponse는 응답 객체이다. 여기에 401 상태 코드를 설정하여 응답을 클라이언트에 보낸다.
    // AuthenticationException는 발생한 인증 예외 객체이다. 인증이 실패한 이유에 대한 정보를 포함하고 있다.
    @Override
    public void commence(HttpServletRequest servletRequest,
                         HttpServletResponse servletResponse,
                         AuthenticationException authenticationException) throws IOException {

        // 인증 실패 또는 인증이 없는 사용자가 보호된 리소스에 접근했을 때, 클라이언트에게 401 Unauthorized 상태 코드를 응답한다.
        servletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }
}

// 이 클래스는 Spring Security에서 정의한 AuthenticationEntryPoint를 구현하고 있으며,
// 인증 되지 않은 사용자가 보호된 리소스에 접근하려고 할 때 이 엔트리 포인트가 호출된다.
// JWT 토큰이 만료되었거나 잘못된 JWT 토큰을 가진 사용자가 보호된 엔드포인트에 접근하려고 할 때
// 이 클래스의 commence 메서드가 호출되어 401 Unauthorized 응답을 보낸다.