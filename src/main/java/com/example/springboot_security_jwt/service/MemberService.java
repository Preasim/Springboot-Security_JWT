package com.example.springboot_security_jwt.service;

import com.example.springboot_security_jwt.dto.MemberDto;
import com.example.springboot_security_jwt.entity.Authority;
import com.example.springboot_security_jwt.entity.Member;
import com.example.springboot_security_jwt.repository.MemberRepository;
import com.example.springboot_security_jwt.util.SecurityUtil;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;

@Service
@AllArgsConstructor
public class MemberService {
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    // 이 메서드가 트랜잭션으로 처리된다. 즉, 데이터베이스 작업이 성공적으로 완료되지 않으면 모든 변경 사항이 롤백된다.
    @Transactional
    public MemberDto signup(MemberDto memberDto) {
        // memberRepository를 사용해 username을 기준으로 기존 사용자 정보를 조회한다.
        // 사용자가 이미 존재하면 예외를 발생시켜 가입을 중단한다.
        if (memberRepository.findOneWithAuthoritiesByUsername(memberDto.getUsername()).orElse(null) != null) {
            throw new RuntimeException("이미 가입되어 있는 유저입니다.");
        }

        // 사용자의 권한을 나타내는 객체이다. ROLE_USER 권한을 부여한다.
        Authority authority = Authority.builder()
            .authorityName("ROLE_USER")
            .build();

        Member member = Member.builder()
            .username(memberDto.getUsername())
            .password(passwordEncoder.encode(memberDto.getPassword()))
            .nickname(memberDto.getNickname())
            // 권한을 Set으로 설정하는데, 이 경우 단일 권한 ROLE_USER만 설정된다.
            // Collections.singleton(T element) 메서드는 인자로 전달된 객체 element를 포함하는 불변의 Set을 반환한다.
            // Set은 크기가 1이며, 오직 하나의 요소만을 포함한다.
            .authorities(Collections.singleton(authority))
            .build();

        return MemberDto.from(memberRepository.save(member));
    }

    // 읽기 전용 트랜잭션으로 동작하여, 데이터베이스의 상태를 변경하지 않음을 보장한다. 성능 최적화 효과도 있다.
    @Transactional(readOnly = true)
    // username에 해당하는 사용자의 정보를 조회한다.
    public MemberDto getUserWithAuthorities(String username) {
        return MemberDto.from(memberRepository.findOneWithAuthoritiesByUsername(username).orElse(null));
    }

    @Transactional(readOnly = true)
    // 현재 인증된 사용자의 이름을 가져온다. 현재 로그인된 사용자에 해당한다.
    public MemberDto getMyUserWithAuthorities() {
        return MemberDto.from(
            SecurityUtil.getCurrentUsername()
                .flatMap(memberRepository::findOneWithAuthoritiesByUsername)
                .orElseThrow(() -> new RuntimeException("Member not found"))
        );
    }
}
