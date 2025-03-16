---
layout: post
title: "Burp Academy-Access control관련 취약점: Unprotected admin functionality"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, API Testing]
toc: true
last_modified_at: 2025-01-14 09:33:00 +0900
---

# 개요
- 문제 주소: https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality
- 취약점 설명페이지: https://portswigger.net/web-security/access-control
- 난이도: APPRENTICE (쉬움)

# 접근 제어(Access Control) 개요
접근제어는 어플리케이션의 제약조건으로, 누가(어떤 것이) 어떤 액션을 수행할 수 있는지, 또는 어떤 리소스에 접근할 수 있는지를 판단한다. 웹 애플리케이션에서 접근제어는 인증(Authentication)과 세션관리(Session Management)에 의존한다. 
- 인증은 유저가 자신이라고 주장하는 것을 확인한다. 
- 세션관리는 연속된 HTTP요청이 동일한 사용자에게서 온 것인지를 판단한다. 
- 접근 제어는 어떤 유저가 하려고 하는 어떤 행동을 허가할지 말지를 결정한다. 

설계관점에서는 다음과 같은 종류가 있다. 

## 수직적 접근제어(Vertical access controls)
수직적 접근제어는 중요 정보를 사용자의 타입에 따라 접근을 제한하는 것이다. 수직적 접근제어에서 다른 타입의 유저는 다른 어플리케이션 기능을 사용한다. 예를 들어, 관리자는 모든 사용자의 계정을 수정하거나 삭제할 수 있지만 일반 사용자는 이러한 작업에 액세스할 수 없다. 수직적 접근 제어는 업무 분리(separation of duties) 및 최소 권한(least privilege)과 같은 비즈니스 정책을 강제하도록 설계된 보안 모델의 보다 세분화된 구현일 수 있다.

## 수평적 접근제어(Horizontal access controls)
수평적 접근제어는 리소스에 대한 접근을 특정 유저들에게 제한하는 방법이다. 예를들어 은행 앱은 사용자 자신의 계정의 거래 내역은 보여주지만 타인의 거래내역은 보여주지 않는다.

## 문맥 의존적인 접근 제어(Context-dependent access controls)
문맥 의존적인 접근 제어는 어플리케이션의 상태나 앱 사용자와의 상호작용에 기초하여 기능이나 리소스에 대한 접근을 제한한다. 문맥 의존적인 접근 제어는 사용자가 잘못된 순서로 액션을 수행하는 것을 방지한다. 예를 들어 EC사이트는 사용자가 구매를 완료한 뒤에 쇼핑카트의 내용을 바꾸는 것을 막을 수 있다. 


# 손상된 접근 제어(Broken access controls) 개요 

## 수직적 권한 상승(Vertical privilege escalation)

### Unprotected functionality
- 관리자 기능같은 것이 아무런 보호없이 개방되어 있는 상태이다. 
- 예측하기 쉬운 경로 혹은 robots.txt 같은 곳에서 경로가 노출되면 악용될 수 있다. 
- 어떤 경우에는 예측하기 힘든 경로를 사용하기도 하면 결국에는 다양한 경로로 노출될 수 있다. 

### Parameter-based access control methods
어떤 앱은 유저가 로그인하면, 접근제어를 실행하는 정보를 유저가 조작가능한 곳에 저장한다. 이는 히든 필드나 쿠키, 쿼리스트링 파라메터 등이다. 유저가 조작가능하므로 쉽게 접근제어를 우회할 수 있다. 

```
https://insecure-website.com/login/home.jsp?admin=true
https://insecure-website.com/login/home.jsp?role=1
```

### Broken access control resulting from platform misconfiguration
어떤 앱은 플랫폼 레이어에서 접근제어를 수행한다. 예를들어 다음과 같은 룰이 설정되어 있을 수 있다. 어딘가 설정이 잘못되면 구멍이 생길 수 있다. 

```
DENY: POST, /admin/deleteUser, managers
```

### Broken access control resulting from URL-matching discrepancies

## 수평적 권한 상승(Horizontal privilege escalation)

## Horizontal to vertical privilege escalation

## Insecure direct object references

## Referer-based access control

## Location-based access control

# 문제 개요
- 이 랩에는 보호되지 않은 관리자 패널이 있다. 
- carlos유저를 삭제하면 랩이 풀린다. 

```
This lab has an unprotected admin panel.

Solve the lab by deleting the user carlos.

```

# 풀이
1. robots.txt에 접근하면 다음이 보인다. 

```
User-agent: *
Disallow: /administrator-panel

```

2. /administrator-panel 로 접근해보면 관리자 패널이 나타난다. 

![](/images/burp-academy-access-control-1.png)

3. carlos 유저를 삭제하면 랩이 풀린다. 

![](/images/burp-academy-access-control-1-success.png)