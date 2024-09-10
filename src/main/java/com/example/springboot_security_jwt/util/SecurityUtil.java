package com.example.springboot_security_jwt.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

public class SecurityUtil {
    private static final Logger logger = LoggerFactory.getLogger(SecurityUtil.class);

    // 이 클래스의 생성자를 private로 선언하여 외부에서 객체를 생성하지 못하지 한다.
    // 이는 유틸리티 클래스라는 점을 명시적으로 나타내며, static 메서드만 사용하도록 제한한다.
    private SecurityUtil() {}

    // Optioanl은 주로 null을 다루기 위한 방법으로 사용된다.
    // 값이 존재할 수도 있고, 존재하지 않을 수도 있는 객체를 감싸는 컨테이너 역할을 한다.
    public static Optional<String> getCurrentUsername() {
        // 현재의 인증 정보를 담고 있는 Authentication 객체를 가져온다.
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // 만약 authentication 객체가 null이라면, 즉 현재 SecurityContext에 인증 정보가 없는 경우 Optional.empty()를 반환한다.
        if (authentication == null) {
            logger.debug("Security Context에 인증 정보가 없습니다.");
            return Optional.empty();
        }

        // authentication.getPrincipal() 는 주로 인증된 사용자 정보를 담고 있는 객체가 들어있다.
        // 이 객체는 UserDetails 타입일 수도 있고, 단순히 사용자 이름이 문자열로 저장되어 있을 수도 있다.
        // 인증된 사용자의 정보가 UserDetails 타입이면, 이를 캐스팅하여 UserDetails 객체로 받아오고
        // 그 안의 getUsername() 메서드를 호출해 사용자 이름을 가져온다.
        // 인증된 사용자 정보가 단순 문자열일 경우, 이 값을 String으로 캐스팅하여 username 변수에 할당한다.
        String username = null;
        if (authentication.getPrincipal() instanceof UserDetails) {
            UserDetails springSecurityUser = (UserDetails) authentication.getPrincipal();
            username = springSecurityUser.getUsername();
        }
        else if (authentication.getPrincipal() instanceof String) {
            username = (String) authentication.getPrincipal();
        }

        // 최종적으로 username을 Optional로 감싸서 반환한다.
        // username이 null일 경우, 빈 Optional을 반환하게 된다.
        // 이는 인증되지 않은 사용자나 principal 정보가 없을 경우를 대비한 안전한 처리 방식이다.
        return Optional.ofNullable(username);
    }
}

// 현재 인증된 사용자의 정보를 가져오는 유틸리티 클래스이다.
// getCurrentUsername() 메서드는 SecurityContextHolder에서 현재 인증 정보를 확인하고, 인증된 사용자의 사용자 이름을 반환한다.
// 인증 정보가 없거나, 인증된 사용자가 없는 경우 로그를 출력하고 빈 Optional을 반환한다.
// 사용자 정보가 UserDetails 타입으로 저장되어 있으면 getUsername()을 통해 이름을 얻고, 그렇지 않으면 문자열로 저장된 이름을 반환한다.