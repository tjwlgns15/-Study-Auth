package com.jihun.authStudy.controller;

import com.jihun.authStudy.dto.SignInRequest;
import com.jihun.authStudy.dto.SignUpRequest;
import com.jihun.authStudy.entity.User;
import com.jihun.authStudy.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequiredArgsConstructor
@RequestMapping("/security-signin")
public class SecurityController {

    private final UserService userService;

    @GetMapping(value = {"", "/"})
    public String home(Model model, Authentication auth) {
        model.addAttribute("loginType", "security-signin");
        model.addAttribute("pageName", "Security");

        if(auth != null) {
            User user = userService.getLoginUserByUsername(auth.getName());
            if (user != null) {
                model.addAttribute("nickname", user.getNickname());
            }
        }

        return "home";
    }

    @GetMapping("/signup")
    public String signupPage(Model model) {
        model.addAttribute("loginType", "security-signin");
        model.addAttribute("pageName", "Security");
        model.addAttribute("request", new SignUpRequest());

        return "signUp";
    }

    @PostMapping("/signup")
    public String signup(@Valid @ModelAttribute("request") SignUpRequest request, BindingResult bindingResult, Model model) {
        model.addAttribute("loginType", "security-signin");
        model.addAttribute("pageName", "Security");

        if(userService.checkUsernameDuplicate(request.getUsername())) {
            bindingResult.addError(new FieldError("request", "username", "로그인 아이디가 중복됩니다."));
        }
        if(userService.checkNicknameDuplicate(request.getNickname())) {
            bindingResult.addError(new FieldError("request", "nickname", "닉네임이 중복됩니다."));
        }
        if (!request.getPassword().equals(request.getPasswordConfirm())) {
            bindingResult.addError(new FieldError("request", "passwordConfirm", "비밀번호가 일치하지 않습니다."));
        }

        if(bindingResult.hasErrors()) {
            model.addAttribute("request", request);
            return "signUp";
        }

        userService.signUp(request);
        return "redirect:/security-signin";
    }

    @GetMapping("/signin")
    public String loginPage(Model model) {
        model.addAttribute("loginType", "security-signin");
        model.addAttribute("pageName", "Security");
        model.addAttribute("request", new SignInRequest());
        return "signIn";
    }

    @GetMapping("/info")
    public String userInfo(Model model, Authentication auth) {
        model.addAttribute("loginType", "security-signin");
        model.addAttribute("pageName", "Security");

        User user = userService.getLoginUserByUsername(auth.getName());

        if(user == null) {
            return "redirect:/security-signin/signin";
        }

        model.addAttribute("user", user);
        return "info";
    }

    @GetMapping("/admin")
    public String adminPage(Model model) {
        model.addAttribute("loginType", "security-signin");
        model.addAttribute("pageName", "Security");

        return "admin";
    }
}
