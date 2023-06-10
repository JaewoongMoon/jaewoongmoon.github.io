---
layout: post
title: "Burp Academy-인증(Authentication) 취약점: Username enumeration via response timing"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, OAuth취약점]
toc: true
---

# 개요
- 인증(Authentication)에 관련된 취약점이다. 
- 취약점 설명 주소: https://portswigger.net/web-security/authentication/password-based
- 문제 주소: : https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing
- 난이도: PRACTITIONER (보통)


# 문제 설명
- 이번에는 존재하는 ID나 패스워드일 경우엔 응답 시간이 다르다는 것 같다. 

```
This lab is vulnerable to username enumeration using its response times. To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

Your credentials: wiener:peter
Candidate usernames
Candidate passwords
```

# 도전

일단 바로 ID 브루트포스해본다. 

그러자 너무 많은 로그인 시도를 했다며 30분후에 다시 시도하라는 메세지가 출력된다. 

`You have made too many incorrect login attempts. Please try again in 30 minute(s).`

![로그인실패](/images/burp-academy-authn-5-1.png)

하나 특이한 점은 8,9,10번째 요청에서는 `Invalid username or password.`라는 응답이었다는 점이다. 

![Invalid username or password](/images/burp-academy-authn-5-2.png)

Intruder에서 응답시간관련 값은 상단의 Columns 메뉴에서 Response received와 Response completed를 선택해서 추가할 수 있따. 

![Intruder 응답시간관련 설정](/images/burp-academy-authn-5-3.png)

응답시간을 비교해보면  Response received 와 Response completed 값이 확연하게 차이나는게 하나 보인다. 

![응답시간비교](/images/burp-academy-authn-5-4.png)

그러나 이 ID를 가지고 패스워드 브루트포스해도 결과는 모두 200 응답 `You have made too many incorrect login attempts. Please try again in 30 minute(s).` 이었다. 