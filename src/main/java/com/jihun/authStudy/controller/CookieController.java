package com.jihun.authStudy.controller;

import com.jihun.authStudy.dto.SignInRequest;
import com.jihun.authStudy.dto.SignUpRequest;
import com.jihun.authStudy.entity.Role;
import com.jihun.authStudy.entity.User;
import com.jihun.authStudy.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.*;

@Controller
@RequiredArgsConstructor
@RequestMapping("/cookie-signin")
public class CookieController {

    private final UserService userService;

    @GetMapping(value = {"", "/"})
    public String home(@CookieValue(name = "userId", required = false) Long userId, Model model) {
        model.addAttribute("loginType", "cookie-signin");
        model.addAttribute("pageName", "Cookie");

        User user = userService.getUserById(userId);

        if (user != null) {
            model.addAttribute("nickname", user.getNickname());
        }
        return "home";
    }

    @GetMapping("/signup")
    public String signUpPage(Model model) {
        model.addAttribute("loginType", "cookie-signin");
        model.addAttribute("pageName", "Cookie");
        model.addAttribute("request", new SignUpRequest());
        return "signUp";
    }

    @PostMapping("/signup")
    public String signUp(@Valid @ModelAttribute("request") SignUpRequest request,
                         BindingResult bindingResult,
                         Model model) {
        model.addAttribute("loginType", "cookie-signin");
        model.addAttribute("pageName", "Cookie");

        if (userService.checkUsernameDuplicate(request.getUsername())) {
            bindingResult.addError(new FieldError("request", "username", "로그인 아이디가 중복됩니다."));
        }
        if (userService.checkNicknameDuplicate(request.getNickname())) {
            bindingResult.addError(new FieldError("request", "nickname", "닉네임이 중복됩니다."));
        }
        if (!request.getPassword().equals(request.getPasswordConfirm())) {
            bindingResult.addError(new FieldError("request", "passwordConfirm", "비밀번호가 일치하지 않습니다."));
        }

        if (bindingResult.hasErrors()) {
            return "signUp";
        }

        userService.signUp(request);
        return "redirect:/cookie-signin";
    }

    @GetMapping("/signin")
    public String signInPage(Model model) {
        model.addAttribute("loginType", "cookie-signin");
        model.addAttribute("pageName", "Cookie");

        model.addAttribute("request", new SignInRequest());
        return "signIn";
    }

    @PostMapping("/signin")
    public String signIn(@ModelAttribute SignInRequest request, BindingResult bindingResult, HttpServletResponse response, Model model) {
        model.addAttribute("loginType", "cookie-signin");
        model.addAttribute("pageName", "Cookie");

        User user = userService.signIn(request);

        if (user == null) {
            bindingResult.reject("signinFail", "로그인 아이디 또는 비밀번호가 틀렸습니다.");
        }

        if (bindingResult.hasErrors()) {
            return "signIn";
        }

        // 쿠키 발급
        Cookie cookie = new Cookie("userId", String.valueOf(user.getId()));
        cookie.setMaxAge(60 * 60);     // 1시간 유효
//        cookie.setHttpOnly(true);      // XSS 방지
//        cookie.setSecure(true);        // HTTPS 전용
//        cookie.setPath("/");           // 전체 경로에서 사용 가능
//        cookie.setDomain("localhost"); // 로컬 테스트용

        response.addCookie(cookie);

        return "redirect:/cookie-signin";
    }

    @GetMapping("/logout")
    public String logout(HttpServletResponse response, Model model) {
        model.addAttribute("loginType", "cookie-signin");
        model.addAttribute("pageName", "Cookie");

        // 쿠키 제거 ( 빈 값, 시간 0 덮어 씌움 )
        Cookie cookie = new Cookie("userId", null);
        cookie.setMaxAge(0);
        response.addCookie(cookie);

        return "redirect:/cookie-signin";
    }

    @GetMapping("/info")
    public String userInfo(@CookieValue(name = "userId", required = false) Long userId, Model model) {
        model.addAttribute("loginType", "cookie-signin");
        model.addAttribute("pageName", "Cookie");

        User user = userService.getUserById(userId);

        if (user == null) {
            return "redirect:/cookie-signin/signin";
        }

        model.addAttribute("user", user);
        return "info";
    }

    @GetMapping("/admin")
    public String adminPage(@CookieValue(name = "userId", required = false) Long userId, Model model) {
        model.addAttribute("loginType", "cookie-signin");
        model.addAttribute("pageName", "Cookie");

        User user = userService.getUserById(userId);

        if(user == null) {
            return "redirect:/cookie-signin/signin";
        }

        if(!user.getRole().equals(Role.ADMIN)) {
            return "redirect:/cookie-signin";
        }

        return "admin";
    }

}
