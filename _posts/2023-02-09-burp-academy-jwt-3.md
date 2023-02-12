---
layout: post
title: "Burp Academy-JWT 세번째 문제:JWT authentication bypass via weak signing key"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, JWT취약점]
toc: true
---


# 개요
- JWT(JSON Web Token) 취약점 세번째 문제이다. 
- JWT 취약점 설명 주소: https://portswigger.net/web-security/jwt
- 문제 주소: https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key
- 난이도: PRACTITIONER (중간)

# 취약점 개요: Brute-forcing secret keys

```
Some signing algorithms, such as HS256 (HMAC + SHA-256), use an arbitrary, standalone string as the secret key. Just like a password, it's crucial that this secret can't be easily guessed or brute-forced by an attacker. Otherwise, they may be able to create JWTs with any header and payload values they like, then use the key to re-sign the token with a valid signature.

When implementing JWT applications, developers sometimes make mistakes like forgetting to change default or placeholder secrets. They may even copy and paste code snippets they find online, then forget to change a hardcoded secret that's provided as an example. In this case, it can be trivial for an attacker to brute-force a server's secret using a wordlist of well-known secrets.

```
- `HS256 (HMAC + SHA-256)` 과 같은 어떤 서명 알고리즘은 임의의 문자열을 시크릿 키로 사용한다. 
- 패스워드 처럼, 이 시크릿 키는 쉽게 추측하거나 브루트 포스로 공격할 수 없어야 한다.
- 그렇지않으면, JWT의 헤더나 페이로드의 값을 쉽게 변조하고 재서명할 수 있게 되어 버린다. 
- JWT 어플리케이션을 구현할 때, 개발자는 가끔 시크릿 키를 알려진 시크릿 키(디폴트 값이나 인터넷 어딘가의 코드 샘플에서 주워온 것 같은)로 사용하는 실수를 범한다.

## 해시캣(hashcat)을 사용해서 시크릿 키 브루트포스 공격하기(Brute-forcing secret keys using hashcat)
- hashcat은 별도 글로 남긴다. 

# 문제 설명
```
This lab uses a JWT-based mechanism for handling sessions. It uses an extremely weak secret key to both sign and verify tokens. This can be easily brute-forced using a wordlist of common secrets.

To solve the lab, first brute-force the website's secret key. Once you've obtained this, use it to sign a modified session token that gives you access to the admin panel at /admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter
```

- 이번에는 시크릿 키를 알아내서 관리자용으로 변조한 JWT를 재서명하면 풀릴 것 같다.

# 풀이
- 주어진 크레덴셜로 로그인해서 다음 JWT를 얻었다. 

```
eyJraWQiOiJjOWQ2MzU1NC1jZDIzLTRmZGItYTM2ZS1lMzJkMGQyY2M3ZGEiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY3NTkxMDUxNH0.-OHWYxXX9NLWnBFf6DoY3fyVTnqC9ZuVPnDf4QO816I
```

이 것을 hashcat으로 해킹해본다. 다음 커맨드를 사용했다.

```sh
# 우선 알려진 JWT 시크릿 키 리스트를 다운로드
curl -O https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list

/usr/local/bin/hashcat -a 0 -m 16500 eyJraWQiOiJjOWQ2MzU1NC1jZDIzLTRmZGItYTM2ZS1lMzJkMGQyY2M3ZGEiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY3NTkxMDUxNH0.-OHWYxXX9NLWnBFf6DoY3fyVTnqC9ZuVPnDf4QO816I ${JWT 시크릿키 리스트 다운로드 경로}
```


