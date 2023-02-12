---
layout: post
title: "Burp Academy-JWT 첫번째 문제:JWT authentication bypass via unverified signature"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, JWT취약점]
toc: true
---


# 개요
- JWT(JSON Web Token) 취약점 첫번째 문제이다. 
- JWT 취약점 설명 주소: https://portswigger.net/web-security/jwt
- 문제 주소: https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature
- 난이도: APPRENTICE (쉬움)

# 취약점 개요: Accepting arbitrary signatures
```
JWT libraries typically provide one method for verifying tokens and another that just decodes them. For example, the Node.js library jsonwebtoken has verify() and decode().

Occasionally, developers confuse these two methods and only pass incoming tokens to the decode() method. This effectively means that the application doesn't verify the signature at all.
```

- JWT를 서버측에서 핸들링할 때 두가지 메서드가 주로 사용된다. 
- `verify`와 `decode`다. 
- 종종, 개발자들은 이 두가지 메서드를 혼동한다. `verify`를 써야하는 곳에 `decode`를 쓰는 경우, JWT의 서명 검증을 하지 않고 통과시켜버리는 취약점이 만들어진다. 


# 문제 설명
```
This lab uses a JWT-based mechanism for handling sessions. Due to implementation flaws, the server doesn't verify the signature of any JWTs that it receives.

To solve the lab, modify your session token to gain access to the admin panel at /admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter
```

- JWT의 내용을 변조해서 admin 기능에 접속할 수 있도록 만들면 된다. 


# 풀이
## 로그인해서 정상적인 JWT획득
- My Account 링크를 클릭하면 로그인 화면으로 이동된다. 
- 문제에서 제공된 크레덴셜(wiener:peter)로 로그인한다. 
- 로그인 시도할 때의 요청과 응답은 다음과 같다. 

```http
POST /login HTTP/1.1
Host: 0a4700ea0436f9f1c0658235004d00c2.web-security-academy.net
Cookie: session=
Content-Length: 68
Cache-Control: max-age=0
Sec-Ch-Ua: "Not_A Brand";v="99", "Google Chrome";v="109", "Chromium";v="109"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
Origin: https://0a4700ea0436f9f1c0658235004d00c2.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a4700ea0436f9f1c0658235004d00c2.web-security-academy.net/login
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7
Connection: close

csrf=e7O1KKhQ7KVfQ4XHL6gjT9YwMUlRsDQy&username=wiener&password=peter
```

```http
HTTP/1.1 302 Found
Location: /my-account
Set-Cookie: session=eyJraWQiOiJlZDg1YWYzYy02ODMyLTQwOWEtYWQ3OS1kZDQ0M2IwMDZlNmUiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY3NTczMTc0NX0.Fy-ExOTjusLQdI5ZWaLlf5bEUBq9KjiJrhCWM5gQRwhluF8mqaRc_mB1RAk0THuBJIwvtyulVN7Z76bu2gZt0N4mQ8YyJ9F5qSlxf560K7ypnHAaSqy-CL8BkVHDkNuaW4ay6chJoPWZlDAKC97VcwHc_PLta-JEaebgMy9tHKNtP7p1zd6s9I5GjFEnDW6WHTMHOxPAcBRkTgJdS4GW3mOMEeIe4b8KIZAamn4k_cR7SFODnDV2c4Ta-PPDl1lFRVwQpgkvnDPEc_oywJneVN9aMwyQn6n4XVC5-Sdi9nMwSGsF4s3zgju6WDNM4ZrtklJDDn_tv3rt43Q6t80w4g; Secure; HttpOnly; SameSite=None
Connection: close
Content-Length: 0


```

## JWT의 내용을 확인하고 변조
- JWT를 간편하게 변조하기 위해서 확장 프로그램을 하나 설치한다. 
- 물론 설치안해도 수작업으로 변조할수도 있지만 확장 프로그램을 사용하면 간편하다. 
- `JWT Editor`라는 프로그램을 설치했다. 

![JWT Editor 설치](/images/burp-academy-jwt-1-jwt-editor-install.png)

- 로그인 후에 다시 홈 화면으로 돌아가면 HTTP 요청을 보낼 때 쿠키로 JWT도 같이 보내진다. 
- 이 요청을 Burp Repeater로 보낸다. 
- Burp Repeater를 보면 가장 오른쪽에 `JSON Web Token`이라는 탭이 추가되어 있는 것을 확인할 수 있다. 
- 여기서 JWT를 간단히 변조할 수 있다. 

![JWT sub필드 변조](/images/burp-academy-jwt-1-1.png)

### 첫번째 시도 
- Raw탭에서 HTTP 요청경로를 `/admin`으로 바꾼다. 
- JSON Web Token탭에서 `sub`필드를 `wiener`에서 `admin`을 바꾼 후 Send버튼을 눌러서 요청을 보내본다. 
- 서버에서 `401 Unauthorized` 응답을 돌려준다. 관리자의 ID는 admin이 아닌 것 같다. 


### 두번째 시도
-  `sub`필드를 `administrator`을 바꾼 후 Send버튼을 눌러서 요청을 보내본다. 
- 이번에는 서버가 200응답을 돌려준다. 
- 응답 HTML 페이지를 보면 유저삭제 경로가 보인다. 

```html 
<div>
    <span>carlos - </span>
    <a href="/admin/delete?username=carlos">Delete</a>
</div>
```

- raw탭의 요청경로를 `/admin/delete?username=carlos`로 바꾼 후 요청을 보낸다. 
- 그러면 서버에서 302 응답을 돌려준다. 

```http
HTTP/1.1 302 Found
Location: /admin
Connection: close
Content-Length: 0


```

그리고 웹 브라우저 문제 화면으로 돌아오면 풀이에 성공했다는 메세지를 확인할 수 있다. 

![문제 해결](/images/burp-academy-jwt-1-success.png)

