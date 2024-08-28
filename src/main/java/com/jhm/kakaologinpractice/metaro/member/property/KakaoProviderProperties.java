package com.jhm.kakaologinpractice.metaro.member.property;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "spring.security.oauth2.client.provider.kakao")
public class KakaoProviderProperties {
    private String tokenUri;
    private String userInfoUri;
}