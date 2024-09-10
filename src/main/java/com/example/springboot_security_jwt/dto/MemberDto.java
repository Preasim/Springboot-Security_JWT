package com.example.springboot_security_jwt.dto;

import com.example.springboot_security_jwt.entity.Member;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.*;

import java.util.Set;
import java.util.stream.Collectors;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class MemberDto {

    @NotNull
    @Size(min = 3, max = 50)
    private String username;

    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @NotNull
    @Size(min = 3, max = 100)
    private String password;

    @NotNull
    @Size(min = 3, max = 50)
    private String nickname;

    // 사용자의 권한을 담고 있는 AuthorityDto 객체들의 집합 / 사용자의 권한을 포함하는 필드
    private Set<AuthorityDto> authorityDtoSet;

    // Member 객체를 MemberDto로 변환하는 정적 메서드이다.
    public static MemberDto from(Member member) {
        if (member == null) return null;

        return MemberDto.builder()
            .username(member.getUsername())
            .nickname(member.getNickname())
            // Member 객체의 권한 집합을 스트림으로 변환한다.
            .authorityDtoSet(member.getAuthorities().stream()
                // 각 Authority 객체를 AuthorityDto로 변환한다.
                .map(authority -> AuthorityDto.builder().authorityName(authority.getAuthorityName()).build())
                // 변환된 AuthorityDto 객체들을 집합으로 수집한다.
                .collect(Collectors.toSet()))
            .build();
    }
}
