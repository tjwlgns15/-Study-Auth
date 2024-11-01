package com.jihun.authStudy.controller;

import com.jihun.authStudy.dto.SignInRequest;
import com.jihun.authStudy.dto.SignUpRequest;
import com.jihun.authStudy.entity.Role;
import com.jihun.authStudy.entity.User;
import com.jihun.authStudy.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.*;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

@Controller
@RequiredArgsConstructor
@RequestMapping("/session-signin")
public class SessionController {

    private final UserService userService;

    public static Hashtable sessionList = new Hashtable();

    @GetMapping(value = {"", "/"})
    public String home(@SessionAttribute(name = "userId", required = false) Long userId, Model model) {
        model.addAttribute("loginType", "session-signin");
        model.addAttribute("pageName", "Session");

        User user = userService.getUserById(userId);

        if (user != null) {
            model.addAttribute("nickname", user.getNickname());
        }
        return "home";
    }

    @GetMapping("/signup")
    public String signUpPage(Model model) {
        model.addAttribute("loginType", "session-signin");
        model.addAttribute("pageName", "Session");
        model.addAttribute("request", new SignUpRequest());
        return "signUp";
    }

    @PostMapping("/signup")
    public String signUp(@Valid @ModelAttribute("request") SignUpRequest request,
                         BindingResult bindingResult,
                         Model model) {
        model.addAttribute("loginType", "session-signin");
        model.addAttribute("pageName", "Session");

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
        return "redirect:/session-signin";
    }

    @GetMapping("/signin")
    public String signInPage(Model model) {
        model.addAttribute("loginType", "session-signin");
        model.addAttribute("pageName", "Session");

        model.addAttribute("request", new SignInRequest());
        return "signIn";
    }

    @PostMapping("/signin")
    public String signIn(@ModelAttribute SignInRequest request, BindingResult bindingResult, HttpServletRequest httpServletRequest, Model model) {
        model.addAttribute("loginType", "session-signin");
        model.addAttribute("pageName", "Session");

        User user = userService.signIn(request);

        if (user == null) {
            bindingResult.reject("signinFail", "로그인 아이디 또는 비밀번호가 틀렸습니다.");
        }

        if (bindingResult.hasErrors()) {
            return "signIn";
        }

        // 세션 생성 전 기존의 세션 제거 == 세션 고정 공격으로부터 방어
        httpServletRequest.getSession().invalidate();
        // 세션 생성
//        HttpSession session = httpServletRequest.getSession(false); // Get or Null
        HttpSession session = httpServletRequest.getSession(true); // Get or Generate

        session.setAttribute("userId", user.getId());
        session.setMaxInactiveInterval(60 * 60);

        // 세션 목록 확인용
        sessionList.put(session.getId(), session);

        return "redirect:/session-signin";
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest  request, Model model) {
        model.addAttribute("loginType", "session-signin");
        model.addAttribute("pageName", "Session");

        // 세션 있으면 제거
        HttpSession session = request.getSession(false);
        if(session != null) {
            sessionList.remove(session.getId());
            session.invalidate();
        }

        return "redirect:/session-signin";
    }

    @GetMapping("/info")
    public String userInfo(@SessionAttribute(name = "userId", required = false) Long userId, Model model) {
        model.addAttribute("loginType", "session-signin");
        model.addAttribute("pageName", "Session");

        User user = userService.getUserById(userId);

        if (user == null) {
            return "redirect:/session-signin/signin";
        }

        model.addAttribute("user", user);
        return "info";
    }

    @GetMapping("/admin")
    public String adminPage(@SessionAttribute(name = "userId", required = false) Long userId, Model model) {
        model.addAttribute("loginType", "session-signin");
        model.addAttribute("pageName", "Session");

        User user = userService.getUserById(userId);

        if(user == null) {
            return "redirect:/session-signin/signin";
        }

        if(!user.getRole().equals(Role.ADMIN)) {
            return "redirect:/session-signin";
        }

        return "admin";
    }

    @GetMapping("/session-list")
    @ResponseBody
    public Map<String, String> sessionList() {
        // sessionList.elements()로 현재 활성화된 모든 세션 목록
        Enumeration elements = sessionList.elements();

        Map<String, String> lists = new HashMap<>();

        while(elements.hasMoreElements()) {
            HttpSession session = (HttpSession)elements.nextElement();
            lists.put(
                    session.getId(),
                    String.valueOf(session.getAttribute("userId"))
            );
        }

        return lists;
    }
}
