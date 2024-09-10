package com.example.springboot_security_jwt.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

// 이 클래스는 GenericFilterBean을 상속받는다 / 필터로서 동작하는 클래스를 만드는 방식이다.
// 필터는 요청이 처리되기 전에 실행되며, 보안이나 로깅 같은 작업을 수행할 수 있다.
@AllArgsConstructor
public class JwtFilter extends GenericFilterBean {
    private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);
    public static final String AUTHORIZATION_HEADER = "Authorization";

    // TokenProvider 객체는 JWT를 생성하고, 검증하고, JWT에서 인증 정보를 추출하는 데 사용된다.
    private TokenProvider tokenProvider;

    // 필터의 핵심 메서드로, HTTP 요청과 응답을 처리한다.
    // servletRequest와 servletResponse는 각각 요청과 응답 객체이다.
    // filterChain은 다음 필터나 실제 서블릿으로 요청을 전달하는 데 사용된다.
    @Override
    public void doFilter(ServletRequest servletRequest,
                         ServletResponse servletResponse,
                         FilterChain filterChain) throws IOException, ServletException {

        // servletRequest는 ServletRequest 타입이기 때문에 이를 HttpServletRequest로 캐스팅한다.
        // HttpServletRequest는 HTTP 관련 메서드들을 제공한다. (헤더 읽기, URI 읽기 등)
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;

        // 이 메서드를 사용하여 HTTP 요청의 헤더에서 JWT를 추출한다. 추출된 토큰이 없으면 null을 반환한다.
        String jwt = resolveToken(httpServletRequest);

        // 현재 요청의 URI를 가져온다.
        // 이 정보를 통해 요청이 어느 경로로 들어왔는지 알 수 있다. 이 정보는 로그 메시지에서 사용된다.
        String requestURI = httpServletRequest.getRequestURI();

        // jwt 변수가 null이 아니고, 공백이 아닌 값이 있는지를 확인한다.
        // TokenProvider 클래스의 validateToken() 메서드를 호출하여 JWT가 유효한지를 검증한다.
        if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {

            // JWT에서 인증 정보를 추출하여 Authentication 객체를 생성한다. 이 객체는 사용자의 권한 및 인증 상태를 포함한다.
            Authentication authentication = tokenProvider.getAuthentication(jwt);

            // 추출된 Authentication 객체를 SecurityContextHolder에 저장한다.
            // SecurityContextHolder는 애플리케이션의 모든 요청에 대해 사용자 인증 정보를 유지하는 역할을 한다.
            // 이를 통해 이후 요청들은 이 인증 정보를 기반으로 동작한다.
            SecurityContextHolder.getContext().setAuthentication(authentication);
            logger.debug("Security Context에 '{}' 인증 정보를 저장했습니다, uri: {}", authentication.getName(), requestURI);
        }
        else {
             logger.debug("유효한 JWT 토큰이 없습니다, uri: {}", requestURI);
        }

        // 현재 필터가 할 일을 마쳤으므로 다음 필터로 요청을 전달한다.
        filterChain.doFilter(servletRequest, servletResponse);
    }

    private String resolveToken(HttpServletRequest request) {
        // HTTP 요청의 Authorization 헤더에서 값을 가져온다. 이 헤더는 Bearer 토큰 형식으로 JWT를 포함할 수 있다.
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);

        // Authorization 헤더가 Bearer로 시작하는지 확인한다. Bearer는 표준적인 JWT 인증 방식의 접두어이다.
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            // 접두어 Bearer 이후의 실제 토큰만 추출해서 반환한다.
            return bearerToken.substring(7);
        }

        return null;
    }
}

//이 필터는 HTTP 요청의 Authorization 헤더에서 JWT를 추출하고, 유효성을 검증한 후
//해당 인증 정보를 Spring Security의 SecurityContextHolder에 저장한다.
//그 과정에서 JWT가 유효하지 않으면 인증을 설정하지 않고, 필터 체인을 통해 다음 단계로 요청을 전달한다.