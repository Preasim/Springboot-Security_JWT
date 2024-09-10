package com.example.springboot_security_jwt.repository;

import com.example.springboot_security_jwt.entity.Member;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {

    // @EntityGraph는 JPA에서 엔티티를 조회할 때, 연관된 엔티티들을 함께 가져오는 데 사용되는 어노테이션이다.
    // 이 어노테이션을 사용하면 특정 엔티티와 연관된 엔티티를 한 번의 쿼리로 효율적으로 로드할 수 있다.
    // attributePaths의 authorities는 MemberEntity의 authorities 속성을 나타낸다.
    @EntityGraph(attributePaths = "authorities")
    Optional<Member> findOneWithAuthoritiesByUsername(String username);
}
