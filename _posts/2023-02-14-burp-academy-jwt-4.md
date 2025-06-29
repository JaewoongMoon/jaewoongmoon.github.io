---
layout: post
title: "Burp Academy-JWT 네번째 문제:JWT authentication bypass via jwk header injection"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, JWT취약점]
toc: true
last_modified_at: 2025-03-26 21:55:00 +0900
---


# 개요
- JWT(JSON Web Token) 취약점 네번째 문제이다. 
- `jwk 헤더 인젝션`에 대한 문제이다. 
- JWT 취약점 설명 주소: https://portswigger.net/web-security/jwt
- 문제 주소: https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jwk-header-injection
- 난이도: PRACTITIONER (중간)

# jwk 파라메터를 통한 자기서명 JWT 주입: Injecting self-signed JWTs via the jwk parameter
JWS 스펙에 따르면, `alg`파라메터만이 필수값이다. 실제 JWT토큰에서는 다른 파라메터도 사용된다. 다음은 해커들이 주로 흥미를 가지는 파라메터들이다. 이 (유저가 컨트롤 가능한) 파라메터들을 통해 서버에게 어디서 키를 가져오라고 지시할 수 있다.
- jwk (JSON Web Key) - 내장된 키 (Provides an embedded JSON object representing the key)
- jku (JSON Web Key Set URL) - 키를 가져올 URL (Provides a URL from which servers can fetch a set of keys containing the correct key)
- kid (Key ID) - 서버가 식별가능한 키 ID (Provides an ID that servers can use to identify the correct key in cases where there are multiple keys to choose from. Depending on the format of the key, this may have a matching kid parameter)

다음은 `jwk`파라메터를 포함하는 JWT 헤더의 예이다. 

```json
{
    "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
    "typ": "JWT",
    "alg": "RS256",
    "jwk": {
        "kty": "RSA",
        "e": "AQAB",
        "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
        "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9m"
    }
}
```

정상적인 경우라면 서버는 제한된 화이트리스트의 공개키 중에서 JWT 서명을 검증할 공개키를 선택해야 한다. 그러나 잘못 설정된 서버는 jwk파라메터에 내장된 키를 가지고 서명 검증을 시도한다. 

# 문제 개요 
- 이 랩은 JWT 기반으로 세션을 처리한다. 서버는 JWT헤더의 jwk 파라메터를 지원한다. 이는 때때로 토큰안에 검증용 키를 내장(임베딩)하는데 사용된다. 하지만 이 경우, 그러나 제공된 키가 신뢰할 수 있는 출처에서 왔는지 확인하지 못한다. 
- 랩을 풀려면, JWT토큰을 변조하고 서명한 후, 관리자 패널(/admin)에 접근하여 carlos유저를 삭제하면 된다.
- wiener:peter 크레덴셜을 사용하여 로그인 가능하다. 

```
This lab uses a JWT-based mechanism for handling sessions. The server supports the jwk parameter in the JWT header. This is sometimes used to embed the correct verification key directly in the token. However, it fails to check whether the provided key came from a trusted source.

To solve the lab, modify and sign a JWT that gives you access to the admin panel at /admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter
```

# 풀이
1. 먼저 정상적인 JWT를 획득한다. `wiener:peter`크레덴셜로 로그인한 후에 정상적인 JWT를 얻어낸다. 

```http
HTTP/1.1 302 Found
Location: /my-account
Set-Cookie: session=eyJraWQiOiI0YmEyMGY0Zi03M2JjLTRmMDAtOWE4My01ZDVlZWM4NmYxMWIiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY3NjMzNjMyOX0.QvgjdXX54pCGcaBu3CFi-SLwHTWaBb7YBYTCdKSt1C8TFPOpwy-sXRBYJjamxaNkuLJFR1jyVIgTYZFW_M0V18LsgimQmL1b0PFog67L4S3LTcsZ0U1a3YFm_OjrILR_EGFMrb1leoyb5kxw-nlmHcOifRnRtbM8zxdlrx2VwFh2FOLX9hJ7gU_uF16pbz1WpUCGFa9JxhEU3wwGfWlUN2o1nGECkyHW66MJYohwXY09Qo5Zyg-YY8sFOw2w3F3mIZK72SfzeusTzku4o346dPHpmDdfy1rCTQ9kvPks3hoMcgmWmLTyycUaBaafvNkJJYUMUptqxv2X4MFcI4FBuA; Secure; HttpOnly; SameSite=None
Connection: close
Content-Length: 0


```

2. 이어서 JWT를 변조한다. 이번에도 마찬가지로 JWT Editor 확장 프로그램을 사용한다. GET 요청을 Repeater로 보낸후 JWT Editor탭에서 값을 변조한다. `sub`파라메터의 값을 `administrator`로 바꾸고 요청하는 경로를 /admin으로 수정한다. 

3. 공격에 사용할 키를 생성한다. JWT Editor Keys 메뉴에서 New RSA key를 클릭한다. 

![RSA Key생성-1](/images/burp-academy-jwt-4-1.png)

RSA Key 팝업이 나타난다. Generate버튼을 클릭하고 OK를 눌러서 저장해둔다. 

![RSA Key생성-2](/images/burp-academy-jwt-4-2.png)

4. 이제 변조된 JWT를 HTTP 요청을 보낼 준비를 한다.  HTTP요청을 Repeater로 보내고, JWT Editor탭에서 Attack 버튼을 클릭한다. 

![공격수행-1](/images/burp-academy-jwt-4-3.png)

Embedded JWK 를 선택한다. 이렇게 하면 위의 과정에서 생성해둔 키가 선택된다. 

![공격수행-2](/images/burp-academy-jwt-4-4.png)

5. 요청을 보내본다. 200응답이 돌아왔다. 관리자 경로 접근에 성공했다!

![HTTP요청-1](/images/burp-academy-jwt-4-5.png)

6. carlos 유저를 삭제하는 요청을 보낸다. 유저 삭제에 성공하고 302응답이 돌아온다. 

![HTTP요청-2](/images/burp-academy-jwt-4-6.png)

7. 랩이 풀렸다. 

![성공](/images/burp-academy-jwt-4-success.png)


