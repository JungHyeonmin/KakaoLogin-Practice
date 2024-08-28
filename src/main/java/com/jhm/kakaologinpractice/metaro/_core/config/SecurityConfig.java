package com.jhm.kakaologinpractice.metaro._core.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jhm.kakaologinpractice.metaro._core.error.ErrorCode;
import com.jhm.kakaologinpractice.metaro._core.jwt.JWTTokenFilter;
import com.jhm.kakaologinpractice.metaro._core.jwt.JWTTokenProvider;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JWTTokenProvider jwtTokenProvider;

    private static final String[] WHITE_LIST = {
            "/api/auth/**",
            "/v3/api-docs/**",       // Swagger 문서
            "/swagger-ui/**",        // Swagger UI
            "/swagger-ui.html",     // Swagger UI HTML
            "/api/tarot/**"
    };

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public MvcRequestMatcher.Builder mvcRequestMatcherBuilder(HandlerMappingIntrospector introspector) {
        return new MvcRequestMatcher.Builder(introspector);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity, MvcRequestMatcher.Builder mvc) throws Exception {

        httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement((sessionManagement) ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests((request) -> request
                        .requestMatchers(this.createMvcRequestMatcherForWhiteList(mvc)).permitAll()
                        .anyRequest().authenticated())
                .oauth2Login(oauth2 -> oauth2
                        .defaultSuccessUrl("/loginSuccess")
                        .failureUrl("/loginFailure"))
                .exceptionHandling(exception -> {
                    exception.authenticationEntryPoint(authenticationEntryPoint());
                    exception.accessDeniedHandler(accessDeniedHandler());
                })
                .addFilterBefore(new JWTTokenFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class);

        // Spring Security Custom Filter 적용 - Form '인증'에 대해서 적용

        return httpSecurity.build();
    }

    private MvcRequestMatcher[] createMvcRequestMatcherForWhiteList(MvcRequestMatcher.Builder mvc) {
        return Stream.of(WHITE_LIST).map(mvc::pattern).toArray(MvcRequestMatcher[]::new);
    }

    private AuthenticationEntryPoint authenticationEntryPoint() {
        return (request, response, authException) -> {
            getResponse(response, ErrorCode.FAILED_AUTHENTICATION, HttpServletResponse.SC_UNAUTHORIZED);
        };
    }

    private AccessDeniedHandler accessDeniedHandler() {
        return (request, response, accessDeniedException) -> {
            getResponse(response, ErrorCode.ACCESS_DENIED, HttpServletResponse.SC_FORBIDDEN);
        };
    }

    private static void getResponse(HttpServletResponse response, ErrorCode errorCode, int status) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");

        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("success", false);
        errorDetails.put("response", null);
        Map<String, Object> error = new HashMap<>();
        error.put("errorCode", errorCode.getErrorCode());
        error.put("message", errorCode.getMessage());
        error.put("status", status);
        error.put("timestamp", LocalDateTime.now().toString());
        errorDetails.put("error", error);

        ObjectMapper objectMapper = new ObjectMapper();
        String jsonResponse = objectMapper.writeValueAsString(errorDetails);

        // UTF-8로 인코딩된 JSON 문자열을 바이트 배열로 변환하여 응답에 쓰기
        response.getOutputStream().write(jsonResponse.getBytes(StandardCharsets.UTF_8));
    }
}
