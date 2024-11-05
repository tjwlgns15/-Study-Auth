package com.jihun.authStudy.config;

import com.jihun.authStudy.entity.Role;
import com.jihun.authStudy.filter.JwtTokenFilter;
import com.jihun.authStudy.handler.MyAccessDeniedHandler;
import com.jihun.authStudy.handler.MyAuthenticationEntryPoint;
import com.jihun.authStudy.service.PrincipalOauth2UserService;
import com.jihun.authStudy.service.UserService;
import com.jihun.authStudy.utils.JwtTokenUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    /*    //  form 로그인
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                // 인증, 인가가 필요한 URL
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/security-signin/info").authenticated()                     // 인가 필요
                        .requestMatchers("/security-signin/admin").hasRole("ADMIN")                   // 필요 인가(권한) 지정
                        .anyRequest().permitAll()                                                       // 그 외의 요청 인가 필요 x
                )
                .formLogin(form -> form
                        .usernameParameter("username")
                        .passwordParameter("password")
                        .loginPage("/security-signin/signin")
                        .defaultSuccessUrl("/security-signin")                                          // 성공 시 이동 URL
                        .failureUrl("/security-signin/signin")                       // 실패 시 이동 URL
                )
                .logout(logout -> logout
                        .logoutUrl("/security-signin/logout")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                );

        return http.build();
    }
    */

    /*
    private final UserService userService;

    @Value("${jwt.key}")
    private String secretKey;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .httpBasic(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement((configurer) -> configurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(new JwtTokenFilter(userService, secretKey), UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(
                        (requests) -> requests
                                .requestMatchers("/jwt-signin/info").authenticated()
                                .requestMatchers("/jwt-signin/admin").hasAuthority(Role.ADMIN.name())
                                .anyRequest().permitAll()
                )
                .build();
    }
    */

    private final PrincipalOauth2UserService principalOauth2UserService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        // 인증
                        .requestMatchers("/security-signin/info").authenticated()
                        // 인가
                        .requestMatchers("/security-signin/admin/**").hasAuthority(Role.ADMIN.name())
                        .anyRequest().permitAll()
                )
                // Form Login 방식
                .formLogin(form -> form
                        // 로그인 파라미터
                        .usernameParameter("username")
                        .passwordParameter("password")
                        .loginPage("/security-signin/signin")
                        .defaultSuccessUrl("/security-signin")
                        .failureUrl("/security-signin/signin")
                )
                .logout(logout -> logout
                        .logoutUrl("/security-signin/logout")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                )
                // OAuth 로그인
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/security-signin/signin")
                        .defaultSuccessUrl("/security-signin")
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(principalOauth2UserService)
                        )
                )
                // 예외 처리
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(new MyAuthenticationEntryPoint())
                        .accessDeniedHandler(new MyAccessDeniedHandler())
                );

        return http.build();
    }
}
