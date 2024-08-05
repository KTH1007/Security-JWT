package me.tae.tutorial.config;

import lombok.RequiredArgsConstructor;
import me.tae.tutorial.jwt.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http

                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers("/api/hello",
                                "/h2-console/**",
                                "/api/authenticate",
                                "/api/signup",
                                "/favicon.ico"
                        ).permitAll()
                        .anyRequest()
                        .authenticated()
                )
                .cors(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                // security 로직에 JwtFilter 등록
                .addFilterBefore(
                        new JwtFilter(tokenProvider),
                        UsernamePasswordAuthenticationFilter.class
                )
                // 인증되지 않은 사용자가 보호된 리소스에 접근하려고 할 때 호출되는 엔트리 포인트를 설정
                // 인증은 되었지만 해당 리소스에 대한 접근 권한이 없는 사용자가 접근하려고 할 때 호출되는 핸들러를 설정
                .exceptionHandling(exceptionHandling -> exceptionHandling.authenticationEntryPoint(jwtAuthenticationEntryPoint)
                        .accessDeniedHandler(jwtAccessDeniedHandler))
                // 세션을 사용하지 않기 때문에 STATELESS로 설정
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // enable h2-console
                .headers(headers ->
                        headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin)
                )
                // JwtFilter를 addFilterBefore로 등록했던 JwtSecurityConfig class 적용
                .addFilterBefore(new JwtFilter(tokenProvider), UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
