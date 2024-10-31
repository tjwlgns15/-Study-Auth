# 🔐 단계별 로그인 구현 스터디

## 📌 목표
로그인 기능을 단계적으로 구현하며 각 방식의 장단점을 파악하고, 보안성과 사용자 경험을 개선하는 과정을 학습합니다.

## 🚀 구현 단계
1. **쿠키 기반 인증**
   - 기본적인 쿠키 저장 방식 구현
   - 쿠키 보안 설정 적용

2. **세션 기반 인증**
   - 서버 측 세션 관리
   - 세션 ID를 통한 사용자 식별

3. **Spring Security**
   - Spring Security 기본 설정
   - 인증/인가 처리 구현

4. **JWT(JSON Web Token)**
   - 토큰 기반 인증 구현
   - Refresh Token 적용

5. **OAuth 2.0 + JWT**
   - 소셜 로그인 연동
   - JWT와 OAuth 통합

## 🛡️ 보안 고려사항
### 1. 비밀번호 암호화
- BCrypt 암호화 적용
- 안전한 비밀번호 정책 설정

### 2. 보안 취약점 대응
- XSS(Cross-Site Scripting) 방어
- CSRF(Cross-Site Request Forgery) 토큰 적용

### 3. 만료 관리
- 세션 타임아웃 설정
- 토큰 만료 시간 관리

## ✨ 사용자 편의 기능
1. **자동 로그인**
   - Remember-Me 기능 구현
   - 보안을 고려한 자동 로그인 처리

2. **로그인 상태 유지**
   - 세션/토큰 갱신 로직
   - 사용자 활동 기반 연장

## 🔍 프로젝트 구조
```
src/
├── main/
│   ├── java/
│   │   └── com/jihun/authStudy/
│   │       ├── config/
│   │       ├── controller/
│   │       ├── service/
│   │       ├── repository/
│   │       └── dto/
│   └── resources/
│       └── templates/
```

## 🛠️ 사용 기술
- Java 17
- Spring Boot
- Spring Security
- Spring Data JPA
- Thymeleaf
- MySQL

## 📝 Study Log
각 단계별 구현 과정과 학습 내용을 기록하며, 발견한 문제점과 해결 방법을 정리합니다.

---
*This project is for studying various authentication methods in Spring Boot applications.*
