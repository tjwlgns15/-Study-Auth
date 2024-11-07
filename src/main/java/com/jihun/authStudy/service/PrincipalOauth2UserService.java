package com.jihun.authStudy.service;

import com.jihun.authStudy.entity.Role;
import com.jihun.authStudy.entity.User;
import com.jihun.authStudy.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

import static com.jihun.authStudy.entity.Role.USER;

@Service
@RequiredArgsConstructor
@Slf4j
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder encoder;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        log.info("getAttributes : {}", oAuth2User.getAttributes());

        OAuth2UserInfo oAuth2UserInfo = null;
        String provider = userRequest.getClientRegistration().getRegistrationId();

        if (provider.equals("google")) {
            log.info("google login request");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if (provider.equals("kakao")) {
            log.info("kakao login request");
            oAuth2UserInfo = new KakaoUserInfo(oAuth2User.getAttributes());
        } else if (provider.equals("naver")) {
            log.info("naver login request");
            oAuth2UserInfo = new NaverUserInfo((Map)oAuth2User.getAttributes().get("response"));
        }

        String providerId = oAuth2UserInfo.getProviderId();
//        String email = oAuth2UserInfo.getEmail();
        String username = provider + "_" + providerId;
        String nickname = oAuth2UserInfo.getName();


        User user = userRepository.findByUsername(username).orElseGet(
                () -> {User newUser = User.builder()
                        .username(username)
                        .nickname(nickname)
                        .provider(provider)
                        .providerId(providerId)
                        .role(USER)
                        .build();
                    return userRepository.save(newUser);
                });
        return new PrincipalDetails(user, oAuth2User.getAttributes());

    }
}
