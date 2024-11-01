package com.jihun.authStudy.service;

import com.jihun.authStudy.entity.User;
import com.jihun.authStudy.repository.UserRepository;
import com.jihun.authStudy.userdetails.PrincipalDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElseThrow(
                () -> new UsernameNotFoundException(username + "를 찾을 수 없습니다.")
        );
        return new PrincipalDetails(user);
    }
}
