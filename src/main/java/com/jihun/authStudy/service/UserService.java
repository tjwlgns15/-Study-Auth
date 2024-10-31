package com.jihun.authStudy.service;

import com.jihun.authStudy.dto.SignInRequest;
import com.jihun.authStudy.dto.SignUpRequest;
import com.jihun.authStudy.entity.User;
import com.jihun.authStudy.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * 아이디 중복 체크
     */
    public boolean checkUsernameDuplicate(String username) {
        return userRepository.existsByUsername(username);
    }

    /**
     * 닉네임 중복 체크
     */
    public boolean checkNicknameDuplicate(String nickname) {
        return userRepository.existsByNickname(nickname);
    }

    /**
     * 회원 가입
     */
    public Long signUp(SignUpRequest request) {
        String encodedPassword = passwordEncoder.encode(request.getPassword());
        User user = request.toEntity(encodedPassword);

        return userRepository.save(user).getId();
    }

    /**
     * 로그인
     */
    public User signIn(SignInRequest request) {
        Optional<User> optionalUser = userRepository.findByUsername(request.getUsername());

        if (optionalUser.isEmpty()) {
            return null;
        }

        if (!passwordEncoder.matches(request.getPassword(), optionalUser.get().getPassword())) {
            return null;
        }
        return optionalUser.get();
    }

    public User getUserById(Long userId) {
        if (userId == null) return null;

        Optional<User> optionalUser = userRepository.findById(userId);
        if (optionalUser.isEmpty()) return null;

        return optionalUser.get();
    }


    /**
     * 로그인 관련 공부이므로 생성 이외의 CRUD는 다루지 않음
     */



}
