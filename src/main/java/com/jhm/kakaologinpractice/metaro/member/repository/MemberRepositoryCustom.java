package com.jhm.kakaologinpractice.metaro.member.repository;


import com.jhm.kakaologinpractice.metaro.member.domain.Member;

import java.util.Optional;

public interface MemberRepositoryCustom {

    Optional<Member> findByEmail(String email);
}
