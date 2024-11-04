package com.jihun.authStudy.controller;

import com.jihun.authStudy.dto.SignInRequest;
import com.jihun.authStudy.dto.SignUpRequest;
import com.jihun.authStudy.entity.User;
import com.jihun.authStudy.service.UserService;
import com.jihun.authStudy.utils.JwtTokenUtil;
import lombok.RequiredArgsConstructor;
import org.apache.coyote.Request;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/jwt-signin")
public class JwtController {

    private final UserService userService;

    @Value("${jwt.key}")
    private String secretKey;
    long expireTimeMs = 1000 * 60 * 60;

    @PostMapping("/signup")
    public String signup(@RequestBody SignUpRequest request) {

        if(userService.checkUsernameDuplicate(request.getUsername())) {
            return "아이디가 중복됩니다.";
        }
        if(userService.checkNicknameDuplicate(request.getNickname())) {
            return "닉네임이 중복됩니다.";
        }
        if(!request.getPassword().equals(request.getPasswordConfirm())) {
            return"바밀번호가 일치하지 않습니다.";
        }

        userService.signUp(request);
        return "회원가입 성공";
    }

    @PostMapping("/signin")
    public String signin(@RequestBody SignInRequest request) {
        User user = userService.signIn(request);

        if(user == null) {
            return"회원정보가 일치하지 않습니다.";
        }

        // 로그인 성공 => Jwt Token 발급
        String jwtToken = JwtTokenUtil.createToken(user.getUsername(), secretKey, expireTimeMs);

        return jwtToken;
    }

    @GetMapping("/info")
    public String userInfo(Authentication auth) {
        User loginUser = userService.getLoginUserByUsername(auth.getName());

        return String.format("loginId : %s\nnickname : %s\nrole : %s",
                loginUser.getUsername(), loginUser.getNickname(), loginUser.getRole().name());
    }

    @GetMapping("/admin")
    public String adminPage() {
        return "관리자 페이지 접근 성공";
    }
}
