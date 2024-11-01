package com.jihun.authStudy.config;

import com.jihun.authStudy.entity.Role;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
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
}
