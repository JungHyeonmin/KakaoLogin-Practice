package com.jhm.kakaologinpractice.metaro.member.controller;


import com.jhm.kakaologinpractice.metaro._core.utils.ApiUtils;
import com.jhm.kakaologinpractice.metaro.member.dto.MemberRequestDTO;
import com.jhm.kakaologinpractice.metaro.member.dto.MemberResponseDTO;
import com.jhm.kakaologinpractice.metaro.member.service.MemberService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


// logging: 정보를 제공하는 일련의 기록인 로그(log)를 생성하도록 시스템을 작성하는 활동


@Slf4j // 로깅 프레임워크의 추상화를 제공해주는 라이브러리
@RequiredArgsConstructor // 생성자 주입을 임의의 코드없이 자동으로 설정해주는 어노테이션
@RestController // RESTFUL 컨트롤러임을 설정
@RequestMapping("/api/auth") // api/auth 이라는 상위 url 을 가지며 하위 url 을 관리한다.
@Tag(name = "회원 인증 API", description = "회원 가입, 로그인, 토큰 재발급, 로그아웃 기능을 제공하는 API") // 테스트 클래스, 메서드에 테스트를 구분하기 위해 사용
public class MemberController {

    private final MemberService memberService;

    /*
          기본 회원 가입
       */
    @Operation(summary = "회원 가입", description = "회원 가입을 처리합니다.")
    @PostMapping("/signup")
    public ResponseEntity<?> signUp(@Valid @RequestBody MemberRequestDTO.signUpDTO requestDTO) {

        memberService.signUp(requestDTO);

        return ResponseEntity.ok().body(ApiUtils.success(null));
    }


    /*
         기본 로그인
      */
    @Operation(summary = "로그인", description = "회원 로그인을 처리하고 인증 토큰을 발급합니다.")
    @PostMapping("/login")
    public ResponseEntity<?> login(HttpServletRequest httpServletRequest, @Valid @RequestBody MemberRequestDTO.loginDTO requestDTO) {

        MemberResponseDTO.authTokenDTO responseDTO = memberService.login(httpServletRequest, requestDTO);

        return ResponseEntity.ok().body(ApiUtils.success(responseDTO));
    }

    /*
       Access Token 재발급 - Refresh Token 필요
    */
    @Operation(summary = "토큰 재발급", description = "Refresh Token을 사용하여 Access Token을 재발급합니다.")
    @PostMapping("/reissue")
    public ResponseEntity<?> reissueToken(HttpServletRequest httpServletRequest) {

        MemberResponseDTO.authTokenDTO responseDTO = memberService.reissueToken(httpServletRequest);

        return ResponseEntity.ok().body(ApiUtils.success(responseDTO));
    }

    /*
        로그아웃 - Refresh Token 필요
     */
    @Operation(summary = "로그아웃", description = "Refresh Token을 사용하여 로그아웃을 처리합니다.")
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest httpServletRequest) {

        log.info("로그아웃 시도");

        memberService.logout(httpServletRequest);

        return ResponseEntity.ok().body(ApiUtils.success(null));
    }
}
