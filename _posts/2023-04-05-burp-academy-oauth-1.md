---
layout: post
title: "Burp Academy-OAuth 첫번째 문제: Authentication bypass via OAuth implicit flow"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, OAuth취약점]
toc: true
---

# 개요
- OAuth 2.0 인증에 관련된 취약점이다. 
- 취약점 설명 주소: https://portswigger.net/web-security/oauth
- 문제 주소: https://portswigger.net/web-security/oauth/lab-oauth-authentication-bypass-via-oauth-implicit-flow
- 난이도: APPRENTICE (쉬움)

# OAuth 2.0 취약점
- OAuth 2.0는 내재적으로 구현 실수가 발생하기 쉽다고 한다. (어떤 취약점들이 있는지, 어떤 구현실수가 있는지 궁금하다)
- OAuth는 유저의 로그인 정보를 어플리케이션측에 노출하지 않고 접근허가를 제공할 수 있는 인증 프레임워크이다. 

## OAuth 2.0은 어떻게 동작하는가?
다음 세개의 구성요소가 있다. 
1. 클라이언트 어플리케이션(Client application): 유저의 데이터에 접근하고 싶은 웹 사이트/웹 어플리케이션
2. 리소스 소유자(Resource owner): 클라이언트 어플리케이션이 접근하고 싶은 데이터를 소유하고 있는 사용자
3. OAuth 서비스 프로바이더: 유저의 데이터와 접근권한을 관리하는 웹 사이트 또는 어플리케이션. 리소스 서버와 인가(authorization) 서버와 통신할 수 있는 API 를 제공함으로서 OAuth 를 서포트한다. 

### OAuth flow와 grant type
다음 단계를 거쳐서 수행된다. 

1. 클라이언트 어플리케이션이 유저의 데이터의 일부분에 접근하고자 하는 요청을 보낸다. 이 때, 어떤 grant type (승인타입)을 사용하고 싶은지와 어떤 종류의 접근(access)을 하고 싶은지 구체적으로 명시한다. 
2. 유저는 OAuth 서비스에 로그인하고 클라이언트 어플리케이션으로부터의 요청을 명시적으로 동의한다. 
3. 클라이언트 어플리케이션은 유저의 데이터에 접근하기 위한 억세스 토큰을 제공받는다. 이 과정은 grant type에 따라 다양할 수 있다. 
4. 클라이언트 어플리케이션은 이 억세스 토큰을 이용해 리소스 서버로부터 데이터를 가져오기 위한 API요청을 보낸다. 

## OAuth grant types
별도의 [OAuth grant types]({% post_url 2023-04-06-burp-oauth-grant-types %}) 페이지에 정리하였다. 


# 문제 개요
문제 사이트는 소셜 미디어 계정으로 로그인할 수 있는 OAuth 서비스를 사용하고 있다. 클라이언트 어플리케이션 측의 구현에 결함이 있어서 공격자의 다른 유저의 계정 비밀번호를 몰라도 그 계정으로 로그인할 수 있다. 카를로스 유저(carlos@carlos-montoya.net)의 계정으로 로그인하면 문제가 풀린다. 일단 자신의 계정 wiener:peter 로 로그인가능하다. 

```
This lab uses an OAuth service to allow users to log in with their social media account. Flawed validation by the client application makes it possible for an attacker to log in to other users' accounts without knowing their password.

To solve the lab, log in to Carlos's account. His email address is carlos@carlos-montoya.net.

You can log in with your own social media account using the following credentials: wiener:peter.

```
# 풀이 
일단 주어진 유저의 정보로 로그인해본다. 로그인할 때의 통신을 Burp proxy로 캡쳐해보면 /authenticate 엔드포인트에 대한 요청이 보인다. 이 요청을 잘 살펴본다. 그러면 다음과 같이 email주소와 토큰이 같이 전송되는 것을 볼 수 있다. 

![wiener유저로 로그인](/images/burp-academy-oauth-1-1.png)

이 요청을 Send to Repeater 기능을 이용해 Repeater로 이동한 후 변조해본다. 정상적일 때는 302 응답이 반환된다. email파라메터를 변조한 후 보내도 302응답이 반환될까? email파라메터를 carlos@carlos-montoya.net로 변조한 후 요청을 보내본다. 302응답이 반환되었다. calos 유저의 세션토큰을 얻는데 성공한 것 같다. 이 때의 session 쿠키값을 복사해둔다. 

![email파라메터 변조](/images/burp-academy-oauth-1-2.png)

톱 페이지 요청 (GET /)을 또 다른 Repeater 탭으로 가져와서 위의 과정에서 얻은 calos 유저의 session 쿠키값으로 설정해서 테스트해본다. 200응답이 반환되었다! 

![calos 유저의 session 쿠키값으로 접근시도](/images/burp-academy-oauth-1-3.png)

웹 페이지 화면을 보면 문제 풀이에 성공했다는 메세지가 보인다. 
![풀이 성공](/images/burp-academy-oauth-1-success.png)


