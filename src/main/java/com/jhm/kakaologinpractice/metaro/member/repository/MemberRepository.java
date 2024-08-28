package com.jhm.kakaologinpractice.metaro.member.repository;

import com.jhm.kakaologinpractice.metaro.member.domain.Member;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface MemberRepository extends JpaRepository<Member, Long>, MemberRepositoryCustom {

}