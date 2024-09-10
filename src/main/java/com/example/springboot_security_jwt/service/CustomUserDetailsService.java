package com.example.springboot_security_jwt.service;

import com.example.springboot_security_jwt.entity.Member;
import com.example.springboot_security_jwt.repository.MemberRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Component("userDetailsService")
@AllArgsConstructor
// UserDetailsService 인터페이스는 Spring Security에서 사용자 세부 정보를 로드하는 데 필요한 메서드를 정의한다.
public class CustomUserDetailsService implements UserDetailsService {
    private final MemberRepository userRepository;

    // loadUserByUsername 메서드는 Spring Security에서 사용자 인증을 처리하는 데 사용된다.
    // 이 메서드는 UserDetailsService 인터페이스의 구현으로, 주어진 사용자 이름을 기반으로 사용자 정보를 로드한다.
    @Override
    @Transactional
    public UserDetails loadUserByUsername(final String username) {
        return userRepository.findOneWithAuthoritiesByUsername(username)
            .map(user -> createUser(username, user))
            .orElseThrow(() -> new UsernameNotFoundException(username + " -> 데이터베이스에서 찾을 수 없습니다."));
    }

    // 이 메서드는 private 접근 제어자로 정의되어 있어, CustomUserDetailsService 클래스 내에서만 호출될 수 있다.
    // org.springframework.security.core.userdetails.User는 Spring Security에서 사용되는 UserDetails의 구현체로, 사용자 정보를 담고 있다.
    private org.springframework.security.core.userdetails.User createUser(String username, Member member) {

        // !member.isActivated() 메서드는 사용자가 활성화되어 있는지를 확인한다.
        // 이 검사는 인증 프로세스 중 활성화되지 않은 사용자 계정을 방지하기 위한 것이다.
        if (!member.isActivated()) {
            throw new RuntimeException(username + " -> 활성화되어 있지 않습니다.");
        }

        // member.getAuthorities() 메서드를 호출하여 Member 객체에 할당된 권한 목록을 가져온다.
        List<GrantedAuthority> grantedAuthorities = member.getAuthorities().stream()
            // 각 권한 객체를 SimpleGrantedAuthority 객체로 변환한다.
            // SimpleGrantedAuthority는 Spring Security에서 사용되는 GrantedAuthority의 구현체로, 권한의 이름을 나타낸다.
            .map(authority -> new SimpleGrantedAuthority(authority.getAuthorityName()))
            // 변환된 권한을 리스트로 수집한다. 이 리스트는 User 객체에 전달되어 권한 정보를 제공한다.
            .collect(Collectors.toList());

        // 사용자 정보를 Spring Security에서 사용하는 형태로 변환한다.
        // 사용자 이름, 비밀번호, 권한 리스트를 설정하고, User 객체를 생성하여 반환한다.
        return new org.springframework.security.core.userdetails.User(member.getUsername(),
            member.getPassword(),
            grantedAuthorities);
    }
}

// 1. 활성화 상태 확인: 입력받은 Member 객체가 활성화되어 있는지 확인한다.
// 2. 권한 변환: Member 객체의 권한을 스트림을 통해 SimpleGrantedAuthority 객체로 변환하고, 이 변환된 권한을 리스트로 수집한다.
// 3. User 객체 생성: 변환된 권한 리스트와 사용자 이름, 비밀번호를 사용하여 Spring Security의 User 객체를 생성하고 반환한다.
// 이 클래스는 UserDetailsService의 loadUserByUsername 메서드를 구현하여,
// Member 객체를 Spring Security가 이해할 수 있는 UserDetails 객체로 변환하여 인증 과정에서 사용한다.