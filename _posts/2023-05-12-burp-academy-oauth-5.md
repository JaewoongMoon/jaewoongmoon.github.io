---
layout: post
title: "Burp Academy-OAuth 다섯번째 문제: SSRF via OpenID dynamic client registration"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, OAuth취약점]
toc: true
---

# 개요
- OAuth 2.0 인증에 관련된 취약점이다. 
- 취약점 설명 주소: https://portswigger.net/web-security/oauth/openid
- 문제 주소: https://portswigger.net/web-security/oauth/openid/lab-oauth-ssrf-via-openid-dynamic-client-registration
- 난이도: PRACTITIONER (보통)

# 문제 설명
- 클라이언트 어플리케이션을 마음대로 등록할 수 있다. 
- client에 대한 데이터가 OAuth 서비스에서 안전하게 사용되고 있지 않다. 따라서 SSRF가 가능하다. 
- SSRF공격을 통해 OAuth관리측에서 `http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/`로 접속하도록 만들어서 OAuth 제공자의 클라우드 환경의 억세스키를 얻어내자. 

```
This lab allows client applications to dynamically register themselves with the OAuth service via a dedicated registration endpoint. Some client-specific data is used in an unsafe way by the OAuth service, which exposes a potential vector for SSRF.

To solve the lab, craft an SSRF attack to access http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/ and steal the secret access key for the OAuth provider's cloud environment.

You can log in to your own account using the following credentials: wiener:peter
```

# 풀이 

## 살펴보기
- 이번 문제는 exploit서버가 존재하지 않는다. 
- 이 웹 사이트는 소셜미디어 계정으로 OAuth로그인이 가능하다. 
- 조금 특별한 점은 소셜 미디어 계정로그인 성공후에 /oauth-callback 으로 웹 사이트로 되돌아오는 부분에 code파라메터가 GET요청으로 되어 있다는 점이다. 

```http 
GET /oauth-callback?code=z6sTlfO2JUbBkWSWYme14Q1RppjWxPoRm5wMclA7G8e HTTP/2
Host: 0a5700d603e8bc4e8466454f00f90035.web-security-academy.net
Cookie: session=Ba7grVUdqT8Xk8gxctS0O5SWDXhIH1rc
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://oauth-0a57007b032ebcc384dc434b02d90026.oauth-server.net/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: cross-site
Sec-Fetch-User: ?1
Te: trailers


```

그리고 로그아웃 후에 다시 로그인을 시도하면 별도로 ID/PW를 물어보지 않고 바로 로그인 된다. 이게 뭔가 힌트가 될지도 모른다. 


## 풀이방법 생각해보기
- 공격목표는 웹사이트의 관리자가 아니라 OAuth 서비스를 제공하는 서버이다. 
- SSRF공격이므로 웹사이트에 OAuth서비스쪽으로 행하는 공격일 것이다. 
- 웹 사이트에서 뭔가 OAuth쪽으로 URL을 던져주는 부분을 찾는다. 
- 특별히 보이지 않는다. 
- 아! 클라이언트를 마음대로 등록할 수 있다고 했다. 그런데 등록하는 부분은 안보인다. 아마 OAuth서비스의 알려진 엔드포인트가 있을 것이다. 
- 몇 가지 테스트를 해본다. /register, /registration, /openid/register, /openid/registration등을 테스트해보자. 