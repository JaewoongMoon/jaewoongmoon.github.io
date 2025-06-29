---
layout: post
title: "Burp Academy-JWT 다섯번째 문제:JWT authentication bypass via jku header injection"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, JWT취약점]
toc: true
last_modified_at: 2025-03-26 21:55:00 +0900
---


# 개요
- `jku`파라메터를 이용한 취약점 문제이다. 
- JWT 취약점 설명 주소: https://portswigger.net/web-security/jwt
- 랩 주소: https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection
- 난이도: PRACTITIONER (중간)

# jku 파라메터를 통해 셀프서명한 JWT를 삽입하기 (Injecting self-signed JWTs via the jku parameter)
`jwk` 파라메터를 이용했을 때 처럼 공개키를 내장시키는 방법이 아니라, `jku`(JWK Set URL)헤더를 이용해서 공개키의 URL을 지정하는 테크닉이다.　키를 제공하는 서버에서 취득가능한 `JWK Set`은 다음과 같이 생겼다. 

```json
{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "75d0ef47-af89-47a9-9061-7c02a610d5ab",
            "n": "o-yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw-fhvsWQ"
        },
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "d8fDFo-fS9-faS14a9-ASf99sa-7c1Ad5abA",
            "n": "fc3f-yy1wpYmffgXBxhAUJzHql79gNNQ_cb33HocCuJolwDqmk6GPM4Y_qTVX67WhsN3JvaFYw-dfg6DH-asAScw"
        }
    ]
}
```

서버에서 구현할 때 JWK는 일반적으로 신뢰할 수 있는 도메인에서만 가져 오도록 한다. 하지만 구현에 버그가 있을 경우 아래와 같은 값을 사용하여 검사를 우회할 수 있다.

```
https://expected-host:fakepassword@evil-host
https://evil-host#expected-host
https://expected-host.evil-host
```

자세한 내용은 아래 URL을 확인한다. 

https://portswigger.net/web-security/ssrf#ssrf-with-whitelist-based-input-filters

# 문제 설명
- 이 랩은 세션을 처리하기 위해 JWT 기반 메커니즘을 사용한다. 
- 서버는 JWT 헤더의 `jku` 매개변수를 지원한다. 그러나 키를 가져오기 전에 제공된 URL이 신뢰할 수 있는 도메인에 들어가 있는지 확인하지 못한다.
- 랩을 풀려면 관리자 패널 `/admin` 에 액세스할 수 있는 JWT를 만든 다음 `carlos` 사용자를 삭제하라. 
- `wiener:peter` 로 로그인할 수 있다. 

```
This lab uses a JWT-based mechanism for handling sessions. The server supports the jku parameter in the JWT header. However, it fails to check whether the provided URL belongs to a trusted domain before fetching the key.

To solve the lab, forge a JWT that gives you access to the admin panel at /admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter
```


# 풀이

## JWK Set 준비
Burp Suite에서 확장 프로그램 `JWT Editor`가 추가되어 있는지 확인한다. JWT Editor탭의 Keys 탭에서 새로운 키를 만든다. [JWT 4번째 문제]({% post_url 2023-02-14-burp-academy-jwt-4 %})에서 시도한 과정대로 새로운 RSA 키를 만든다. 

## JWK Set 제공 서버 준비
만들어진 JWK Set을 제공하는 서버를 준비한다. exploit 서버로 이동해서 헤더와 바디부분을 구성한다. 

Content-Type을 json으로 변경했다. 

```
Content-Type: application/json; charset=utf-8
```

Body 부분에 들어갈 키는 JWT Editor Keys 에서 `Copy Public Key as JWK` 를 선택해서 클립보드에 복사해둔다. 

![RSA Key 복사](/images/burp-academy-jwt-5-1.png)


json 형식이 깨지지 않도록 주의한다. json 형식이 맞지 않으면 문제가 안풀린다. 

```json
{
    "keys": [
       // 키를 여기에 붙여넣기 한다. 
   ]
}
```

다음과 같이 만들었다. 

![JWK Set 서버 ](/images/burp-academy-jwt-5-6.png)

## JWT 변조
HTTP요청을 Repeater 탭으로 보내고 JWT의 값 변조를 시도한다. 

1. Payload의 sub을 administrator로 바꾼다. 
2. Header에 jku를 추가한다. exploit 서버의 URL을 지정한다.
3. kid의 값을 생성한 키셋의 kid로 변경한다. 

아래와 같다. 

```json
{
    "kid": "2adc2aa2-aed0-409d-ba8d-f74ed40a8eaa",
    "alg": "RS256",
    "jku": "https://exploit-0ad500c0043e425cc1ebdf8301dd00c2.exploit-server.net/jwks.json"
}
```

이 상태로 /admin에 접근해보면 401 Unauthorized 응답이 돌아온다. JWT의 서명을 바꾸지 않았기 때문이다. 이어서 JWT의 재서명을 시도한다. 

## JWT 재서명하기 

Repeater의 JSON Web Token 탭에서 Sign버튼을 클릭한다. 

![JWT 재서명](/images/burp-academy-jwt-5-7.png)

팝업이 나타난다. 키(kid)를 선택하고 `Don't modify header`옵션을 선택하고 OK버튼을 누른다. 

![재서명팝업](/images/burp-academy-jwt-5-4.png)


JWT의 서명부분이 바뀐 것을 확인할 수 있다. 이상태에서 HTTP 요청을 보내보면 200응답이 확인된다. 

![admin 경로접근성공](/images/burp-academy-jwt-5-3.png)


## carlos 유저 삭제 
carlos 유저를 삭제하는 요청을 보낸다. 

![유저삭제](/images/burp-academy-jwt-5-5.png)

성공메세지가 보여진다. 

![성공](/images/burp-academy-jwt-5-success.png)
