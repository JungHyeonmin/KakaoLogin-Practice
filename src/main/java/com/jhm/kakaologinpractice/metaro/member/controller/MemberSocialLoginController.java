package com.jhm.kakaologinpractice.metaro.member.controller;

import com.jhm.kakaologinpractice.metaro._core.utils.ApiUtils;
import com.jhm.kakaologinpractice.metaro.member.dto.MemberResponseDTO;
import com.jhm.kakaologinpractice.metaro.member.service.MemberSocialLoginService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/auth")
@Tag(name = "카카오 회원 API", description = "소셜 로그인 및 회원가입 기능을 제공하는 API")
public class MemberSocialLoginController {

    private final MemberSocialLoginService memberSocialLoginService;

    // https://kauth.kakao.com/oauth/authorize?response_type=code&client_id=262c56061ee06d4004d2f9b94db133a4&redirect_uri=http://localhost:8080/api/auth/kakao/login
    // https://kauth.kakao.com/oauth/authorize?response_type=code&client_id=262c56061ee06d4004d2f9b94db133a4&redirect_uri=http://172.16.17.66:8181//api/auth/kakao/login
    /*
        카카오 로그인
     */
    @GetMapping("/kakao/login")
    public ResponseEntity<?> kakaoLogin(@RequestParam(name = "code") String code) {
        MemberResponseDTO.authTokenDTO responseDTO = memberSocialLoginService.kakaoLogin(code);
        return ResponseEntity.ok().body(ApiUtils.success(responseDTO));
    }


}
