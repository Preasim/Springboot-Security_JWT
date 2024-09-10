package com.example.springboot_security_jwt.jwt;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
// AccessDeniedHandler 인터페이스는 사용자가 인증은 되었으나, 특정 리소스에 접근할 권한이 없을 때 호출되는 메서드를 정의한다.
public class JwtAccessDeniedHandler implements AccessDeniedHandler {

    // AccessDeniedHandler 인터페이스의 handle() 메서드를 오버라이드한다.
    // 이 메서드는 Spring Security에서 권한이 없는 사용자가 보호된 리소스에 접근하려 할 때 호출된다.
    @Override
    public void handle(HttpServletRequest servletRequest,
                       HttpServletResponse servletResponse,
                       AccessDeniedException accessDeniedException) throws IOException {

        servletResponse.sendError(HttpServletResponse.SC_FORBIDDEN);
    }
}

// 이 클래스는 Spring Security에서 권한 거부 상황을 처리하는 핵심 구성 요소이다.
// 사용자가 인증은 되었지만 해당 리소스에 접근할 권한이 없을때 403 Forbidden 상태 코드를 반환하는 역할을 한다.