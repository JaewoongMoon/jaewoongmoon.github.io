---
layout: post
title: "Burp Academy-인증(Authentication) 취약점: Username enumeration via different responses"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, OAuth취약점]
toc: true
---

# 개요
- 인증(Authentication)에 관련된 취약점이다. 
- 취약점 설명 주소: https://portswigger.net/web-security/authentication/password-based
- 문제 주소: : https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses
- 난이도: APPRENTICE (쉬움)


# 문제 개요 
ID 와 패스워드의 후보군이 주어져 있다. 브루트포스 테크닉을 사용해서 로그인을 하면된다. 

```
This lab is vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password, which can be found in the following wordlists:

Candidate usernames
Candidate passwords
To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.
```

# 풀이 

## 로그인 과정 관찰
일단 로그인 과정을 관찰해본다. 계정 carlos와 비번123456로 로그인을 시도해봤다. 

```http
POST /login HTTP/2
Host: 0aea00b20312bc8481fd3e51006a008d.web-security-academy.net
Cookie: session=tfdiP7dr7lZEqYoRNd8Ape6lE0x937tI
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 31
Origin: https://0aea00b20312bc8481fd3e51006a008d.web-security-academy.net
Referer: https://0aea00b20312bc8481fd3e51006a008d.web-security-academy.net/login
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers

username=carlos&password=123456
```

응답은 다음과 같다. 로그인에 성공하지 않아도 200 응답이 반환된다. 그리고 `Invalid username`이라는 메세지가 보인다.   
username이 잘못되었다고 친철하게 알려주고 있다. 이 것을 이용하면 브루트포스 공격이 가능할 것 같다. 


```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 2886

...생략
    <section>
        <p class=is-warning>Invalid username</p>
        <form class=login-form method=POST action="/login">
            <label>Username</label>
            <input required type=username name="username">
            <label>Password</label>
            <input required type=password name="password">
            <button class=button type=submit> Log in </button>
        </form>
    </section>
...생략
```


## 어떻게 풀지 생각
- ID나 패스워드 어느한쪽을 고정해서 브루트포스 할 수 있을 것 같다. 
- 일단 패스워드를 고정하고 ID를 브루트포스하는 방법을 써보려고 한다. 
- Burp Intruder를 사용하면 간단하게 테스트할 수 있을 것 같다. 

## 패스워드를 고정하고 ID를 브루트포스
- 로그인 요청을 Burp Intruder로 보낸다 .
- Positions탭에서 username파라메터를 추가(Add버튼)한다. 

![Burp Intruder1](/images/burp-academy-authn-1-1.png)

- Payload탭에서 Payloadtype을 Simplelist로 선택하고, 패스워드 목록을 복사해서 붙여넣기 하고, Start  attack버튼을 클릭한다. 

![Burp Intruder1-username브루트포스](/images/burp-academy-authn-1-2.png)

ec2-user계정에서만 응답이 달랐다. 다른 계정은 Invalid username이 출력되었으나 이 계정에서는 Incorrect Password가 출력되었다. 이 계정이 존재한다는 것을 알 수 있다. 

![Burp Intruder1-결과](/images/burp-academy-authn-1-2-result.png)


## ID를 고정하고 패스워드를 브루트포스 
계정이 존재한다는 것을 알았으니 ID를 고정해서 브루트포스해보자. 

- Positions탭에서 password파라메터를 추가하고 공격을 시도한다.  

![Burp Intruder2](/images/burp-academy-authn-1-3.png)

- 그러면 다음과 같이 한 패스워드에서만 302응답이 반환되는 것을 확인할 수 있다. 

![Burp Intruder2-패스워드브루트포스](/images/burp-academy-authn-1-3-result.png)

이 때의 ID와 패스워드를 가지고 웹 사이트에 로그인하면 문제가 풀렸다는 메세지가 출력된다. 

![Burp Intruder2-패스워드브루트포스](/images/burp-academy-authn-1-success.png)