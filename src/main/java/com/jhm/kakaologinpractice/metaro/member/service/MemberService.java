package com.jhm.kakaologinpractice.metaro.member.service;

import com.jhm.kakaologinpractice.metaro._core.error.ApplicationException;
import com.jhm.kakaologinpractice.metaro._core.error.ErrorCode;
import com.jhm.kakaologinpractice.metaro._core.jwt.JWTTokenProvider;
import com.jhm.kakaologinpractice.metaro._core.utils.ClientUtils;
import com.jhm.kakaologinpractice.metaro.member.domain.Authority;
import com.jhm.kakaologinpractice.metaro.member.domain.Gender;
import com.jhm.kakaologinpractice.metaro.member.domain.Member;
import com.jhm.kakaologinpractice.metaro.member.domain.SocialType;
import com.jhm.kakaologinpractice.metaro.member.dto.MemberRequestDTO;
import com.jhm.kakaologinpractice.metaro.member.dto.MemberResponseDTO;
import com.jhm.kakaologinpractice.metaro.member.repository.MemberRepository;
import com.jhm.kakaologinpractice.metaro.refreshToken.domain.RefreshToken;
import com.jhm.kakaologinpractice.metaro.refreshToken.repository.RefreshTokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.Optional;

@Slf4j
@Transactional(readOnly = false)
@RequiredArgsConstructor
@Service
public class MemberService {

    private final MemberRepository memberRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JWTTokenProvider jwtTokenProvider;

    /*
        기본 회원 가입
     */
    @Transactional // 트랜젝션을 관리하는 어노테이션 (트랜젝션: 데이터베이스의 상태를 일관되게 유지하는 역할-commit, rollback)
    public void signUp(MemberRequestDTO.signUpDTO requestDTO) {

        // 비밀번호 확인-(사용자의 원본 비밀번호, 암호화한 비밀번호)를 비교하는 메서드
        checkValidPassword(requestDTO.password(), passwordEncoder.encode(requestDTO.confirmPassword()));

        // 회원 생성
        Member member = newMember(requestDTO);

        // 회원 저장
        memberRepository.save(member);

    }

    /*
        기본 로그인
     */
    public MemberResponseDTO.authTokenDTO login(HttpServletRequest httpServletRequest, MemberRequestDTO.loginDTO requestDTO) {

        // 1. 이메일 확인
        Member member = findMemberByEmail(requestDTO.email())
                .orElseThrow(() -> new ApplicationException(ErrorCode.EMPTY_EMAIL_MEMBER));

        // 2. 비밀번호 확인
        checkValidPassword(requestDTO.password(), member.getPassword());

        return getAuthTokenDTO(requestDTO.email(), requestDTO.password(), httpServletRequest);
    }

    // 비밀번호 확인
    private void checkValidPassword(String rawPassword, String encodedPassword) {

        log.info("{} {}", rawPassword, encodedPassword); // 원본 비밀번호와 암호화된 비밀번호를 출력해서 확인한다.

        // 비밀번호 검증
        if (!passwordEncoder.matches(rawPassword, encodedPassword)) { // matches: 스프링 시큐리티의 passwordEncoder 인터페이스에 정의된 비밀번호 비교 메서드
            throw new ApplicationException(ErrorCode.INVALID_PASSWORD); // 예외처리 에러코드(INVALID_PASSWORD) 던지기
        }
    }

    protected Optional<Member> findMemberByEmail(String email) {
        log.info("회원 확인 : {}", email);

        return memberRepository.findByEmail(email);
    }

    // 회원 생성
    protected Member newMember(MemberRequestDTO.signUpDTO requestDTO) {
        return Member.builder()
                .name(requestDTO.name())
                .email(requestDTO.email())
                .password(passwordEncoder.encode(requestDTO.password()))
                .gender(Gender.fromString(requestDTO.gender()))
                .socialType(SocialType.NONE)
                .authority(Authority.USER)
                .build();
    }

    // 토큰 발급(Auth:인증)- 이메일, 비밀번호, HttpServletRequest(HTTP 요청 정보를 캡슐화하여 전달)
    protected MemberResponseDTO.authTokenDTO getAuthTokenDTO(String email, String password, HttpServletRequest httpServletRequest) {

        // UsernamePasswordAuthenticationToken: 사용자의 이메일과 비밀번호를 포함하는 인증 토큰 객체를 생성한다.- 스프링시큐리티의 Authentication 객체로 자격 증명을 나타낸다.
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken
                = new UsernamePasswordAuthenticationToken(email, password);

        // AuthenticationManager: 스프링 시큐리티의 인증을 처리하는 인터페이스. 주어진 자격 증명(이메일, 비밀번호)을 검증하고, 그 결과로 Authentication 객체를 반환
        // authenticationManagerBuilder: 애플리케이션 컨텍스트에서 인증 설정을 빌드하는 데 사용한다. 이를 통해 AuthenticationManager 가 생성된다.
        // getObject(): authenticationManagerBuilder 를 사용하여 AuthenticationManager 객체를 생성한다.
        AuthenticationManager manager = authenticationManagerBuilder.getObject();

        // authenticate(): AuthenticationManager 의 메서드. ()안의 이름과 비밀번호를 검증하고  그 결과를 반환하는 메서드
        Authentication authentication = manager.authenticate(usernamePasswordAuthenticationToken);

        // jwtTokenProvider: JWT 토큰의 생성과 검증을 담당하는 클래스.generateToken(): Authentication 객체를 기반으로 JWT 토큰을 생성한다.
        // authTokenDTO: JWT 토큰을 포함한 데이터 전송 객체
        MemberResponseDTO.authTokenDTO authTokenDTO = jwtTokenProvider.generateToken(authentication);

        // 단일 권한 추출 (가정: 단일 권한만 부여됨)- 실제 인증이 이루어지는 부분. 인증이 되면 Authentication 객체가 반환된다. 이 객체는 인증된 사용자의 권한 정보를 포함한다.
        Authority authority = Authority.NONE; // 기본값(enum)

        // authentication: 스프링 시큐리티에서 인증된 사용자를 나타내는 Authentication 객체. 인증된 사용자의 자격 증명(사용자 이름, 비밀번호, 권한 등)과 관련된 정보가 있다.
        // authentication.getAuthorities(): Authentication 객체의 메서드로 사용자가 가진 권한을 Collection<?> extends GrantedAuthority 형식으로 반환한다.
        //      GrantedAuthority: 스프링 시큐리티에서 사용자의 권한을 표현하는 인터페이스(권한: ROLE_ADMIN, ROLE_USER)
        // iterator().next(): 권한 리스트에서 첫 번째 GrantedAuthority 객체를 반환한다.
        // getAuthority(): GrantedAuthority 인터페이스의 메서드로 해당 권한의 이름을 문자열 형식으로 반환한다.
        // !(사용자가 가진 권한을 반환한다.).비어다면() => 사용자가 가진 권한이 비어있지 않다면
        if (!authentication.getAuthorities().isEmpty()) {
            authority = Authority.valueOf(authentication.getAuthorities().iterator().next().getAuthority());
        }

        // refreshToken 추가. refreshToken: 짧은 유효기간의 액세스 토큰을 사용하는 경우, 자동 로그인, 멀티 디바이스 환경에서 인증 관리, 보안 강화를 위해 주기적인 재인증에서 사용한다.
        refreshTokenRepository.save(RefreshToken.builder()
                .userName(authentication.getName())
                .ip(ClientUtils.getClientIp(httpServletRequest))
                .authorities(authority)
                .refreshToken(authTokenDTO.refreshToken())
                .build()
        );

        return authTokenDTO;
    }

    // 토큰 재발급 - 사용자의 리프레시 토큰을 검증하고, 유효한 경우 새로운 갱세스 토큰과 리프레시 토큰을 재발급한다.
    public MemberResponseDTO.authTokenDTO reissueToken(HttpServletRequest httpServletRequest) {

        // Request Header 에서 JWT Token 추출
        String token = jwtTokenProvider.resolveToken(httpServletRequest);

        // 토큰 유효성 검사 - 추출된 JWT 토큰이 유효한지 검사한다. 유효성 검사는 토큰의 만료 시간, 서명(Signature)등을 확인하여 수행한다.
        // validateToken(): 토큰 유효성 검사
        if (token == null || !jwtTokenProvider.validateToken(token)) {
            throw new ApplicationException(ErrorCode.FAILED_VALIDATE_ACCESS_TOKEN);
        }

        // type 확인 - 추출한 토큰이 리프레시 토큰인지 확인한다. JWT 토큰은 액세스 토큰과 리프레시 토큰으로 구분될 수 있다.
        if (!jwtTokenProvider.isRefreshToken(token)) {
            throw new ApplicationException(ErrorCode.IS_NOT_REFRESH_TOKEN);
        }

        // RefreshToken - 리프레시 토큰 조회
        Optional<RefreshToken> refreshToken = refreshTokenRepository.findByRefreshToken(token);

        if (refreshToken.isEmpty()) {
            throw new ApplicationException(ErrorCode.FAILED_GET_RERFRESH_TOKEN);
        }

        // 최초 로그인한 ip와 같은지 확인
        // ClientUtils.getClientIp(httpServletRequest): 현재 요청의 IP 주소를 얻는다.
        String currentIp = ClientUtils.getClientIp(httpServletRequest);
        
        // 현재 요청의 IP 주소와 리프레시 토큰이 처음 저장도니 IP 주소와 비교한다.
        if (!currentIp.equals(refreshToken.get().getIp())) {
            throw new ApplicationException(ErrorCode.DIFFERENT_IP_ADDRESS);
        }

        // 저장된 RefreshToken 정보를 기반으로 JWT Token 생성
        // String.valueOf(): 값을 추출하고 String 타입으로 변환한다.
        // refreshToken.get(): Optional<RefreshToken> 타입의 객체로, 리프레시 토큰 정보를 감싼다.
        // get(): Optional 에서 실제 객체(RefreshToken)를 반환한다.- Optional 이 비어있지 않을 때만 호출해야 한다. 비어있지 않으면 NoSuchElementException 이 발생한다.
        // getId(): RefreshToken 객체의 getId() 메서드는 리프레시 토큰과 관련된 사용자의 고유 ID를 반환한다.

        // Collections.singletonList(): 지정된 객체를 포함하는 불변 리스트로 반환한다.-singletonList() 는 한 개의 요소만 포함할 수 있으며, 이 리스트는 수정할 수 없다.
        // SimpleGrantedAuthority: 스프링 시큐리티에서 사용되는 클래스, 이 클래스는 사용자가 가진 특정 권한(역할)을 캡슐화하여, 스피링 시큐리티가 이를 기반으로 인증 및 인가를 처리할 수 있도록 한다.
        // refreshToken.get().getAuthorities().name(): 사용자가 가진 권한을 나타내는 Authority 열거형 객체를 반환한다.그리고 열거형의 이름을 반환한다.(ROLE_USER)
        MemberResponseDTO.authTokenDTO authTokenDTO = jwtTokenProvider.generateToken(
                String.valueOf(refreshToken.get().getId()), Collections.singletonList(new SimpleGrantedAuthority(refreshToken.get().getAuthorities().name()))
        );

        // RefreshToken Update
        refreshTokenRepository.save(RefreshToken.builder()
                .ip(currentIp) // IP 주소를 업데이트
                .authorities(refreshToken.get().getAuthorities())
                .refreshToken(authTokenDTO.refreshToken())
                .build());

        return authTokenDTO;
    }

    /*
        로그아웃 - 서버는 크랄이언트가 제출한 리프레시 토큰을 검증하고 데이테베이스에서 토큰을 삭제함으로써 사용자의 인증 세션을 종료한다.
    */
    public void logout(HttpServletRequest httpServletRequest) {

        log.info("로그아웃 - Refresh Token 확인");

        // 1. Request Header 에서 JWT token 추출
        String token = jwtTokenProvider.resolveToken(httpServletRequest);

        // 2. 토큰 유효성 검사
        if (token == null || !jwtTokenProvider.validateToken(token)) {
            throw new ApplicationException(ErrorCode.FAILED_VALIDATE__REFRESH_TOKEN);
        }

        // RefreshToken 조회 및 null 체크
        RefreshToken refreshToken = refreshTokenRepository.findByRefreshToken(token)
                .orElseThrow(() -> {
                    log.error("Refresh Token 을 얻을 수 없습니다. 토큰: {}", token);
                    return new ApplicationException(ErrorCode.FAILED_GET_RERFRESH_TOKEN);
                });

        // 4. RefreshToken 삭제
        refreshTokenRepository.delete(refreshToken);
        log.info("로그아웃 성공");
    }
}
