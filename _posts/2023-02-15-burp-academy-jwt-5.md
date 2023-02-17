---
layout: post
title: "Burp Academy-JWT 다섯번째 문제:JWT authentication bypass via jku header injection"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, JWT취약점]
toc: true
---


# 개요
- JWT(JSON Web Token) 취약점 다섯번째 문제이다. 
- `jku 헤더 인젝션`에 대한 문제이다. (이전 문제는 jwk 헤더 인젝션이었다.)
- JWT 취약점 설명 주소: https://portswigger.net/web-security/jwt
- 문제 주소: https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection
- 난이도: PRACTITIONER (중간)

# jku 헤더 인젝션 개요: Injecting self-signed JWTs via the jku parameter
- `jwk` 헤더 파라메터로 공개키를 내장시키는 방법이 아니라, `jku`(JWK Set URL)헤더를 이용해서 공개키의 URL을 지정하는 테크닉이다. 
- `JWK Set`은 다음과 같이 생겼다. 

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

- 서버에서 구현할 때는 JWK는 보통 신뢰하는 도메인에서만 얻어오도록 한다. 그러나 구현에 버그가 있으면 우회하는 것도 가능하다. [이 링크](https://portswigger.net/web-security/ssrf#ssrf-with-whitelist-based-input-filters)}{:target="_blank"}에서 예를 확인할 수 있다. 

# 문제 설명
```
This lab uses a JWT-based mechanism for handling sessions. The server supports the jku parameter in the JWT header. However, it fails to check whether the provided URL belongs to a trusted domain before fetching the key.

To solve the lab, forge a JWT that gives you access to the admin panel at /admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter
```
- 이전 JWT문제들과 마찬가지로 관리자 기능(/admin)에 접근 가능한 JWT를 준비해서 calor유저를 삭제하면 된다. 
- jku 헤더를 이용해서 토큰을 변조해야 한다. 
- 이번에는 `JWK Set`을 제공하는 서버가 필요하다. 이런 경우에는 보통 문제에서 exploit서버를 준비해준다. 
- 어쩌면 문제 서버에 필터링 기능이 있을지도 모른다. 필터링을 우회할 수 있도록 exploit서버의 URL을 조금 변경해야할지도 모른다. 

# 풀이
## JWK Set 준비
JWT Editor Keys 에서 새로운 키를 만든다. 
[JWT 4번째 문제]({% post_url 2023-02-14-burp-academy-jwt-4 %})에서 시도한 과정대로 새로운 RSA 키를 만든다. 

## JWK Set 서버 준비
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

### JWT 값 변조
1. Payload의 sub을 administrator로 바꾼다. 
2. Header에 jku를 추가한다. exploit 서버의 URL을 지정한다.
3. kid의 값을 생성한 키셋의 kid로 변경한다. 

```json
{
    "kid": "2adc2aa2-aed0-409d-ba8d-f74ed40a8eaa",
    "alg": "RS256",
    "jku": "https://exploit-0ad500c0043e425cc1ebdf8301dd00c2.exploit-server.net/jwks.json"
}
```

이 상태로 /admin에 접근해보면 401 Unauthorized 응답이 돌아온다. JWT의 서명을 바꾸지 않았기 때문이다. 

### JWT 재서명하기 

JSON Web Token 탭에서 Sign버튼을 클릭한다. 

![JWT 재서명](/images/burp-academy-jwt-5-7.png)

팝업이 나타난다. 키(kid)를 선택하고 `Don't modify header`옵션을 선택한다. 

![재서명팝업](/images/burp-academy-jwt-5-4.png)


JWT의 서명부분이 바뀐 것을 확인할 수 있다. 이상태에서 HTTP 요청을 보내보면 200응답이 확인된다. 

![admin 경로접근성공](/images/burp-academy-jwt-5-3.png)


calors 유저를 삭제하는 요청을 보낸다. 

![유저삭제](/images/burp-academy-jwt-5-5.png)

성공메세지가 보여진다. 

![성공](/images/burp-academy-jwt-5-success.png)
