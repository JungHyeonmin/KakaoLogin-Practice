package com.jhm.kakaologinpractice.metaro.refreshToken.domain;

import com.jhm.kakaologinpractice.metaro.member.domain.Authority;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;


@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "refresh_token")
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY) // 식별자를 자동으로 생성
    private Long id;

    private String userName;

    private String ip;

    @Enumerated(EnumType.STRING)
    private Authority authorities;

    private String refreshToken;

    @Builder
    public RefreshToken(String userName, String ip, Authority authorities, String refreshToken) {
        this.userName = userName;
        this.ip = ip;
        this.authorities = authorities;
        this.refreshToken = refreshToken;
    }
}