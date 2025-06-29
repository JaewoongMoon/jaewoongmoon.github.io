---
layout: post
title: "Burp Academy-JWT 일곱번째 문제: 알고리즘 컨퓨전을 통한 JWT 인증우회"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, JWT취약점]
toc: true
last_modified_at: 2025-04-07 05:55:00 +0900
---

# 개요
- JWT(JSON Web Token) 취약점 일곱번째 문제이다. 
- JWT authentication bypass via algorithm confusion
- JWT 취약점 설명 주소: https://portswigger.net/web-security/jwt/algorithm-confusion
- 문제 주소: https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion
- 난이도: EXPERT (높음)

# Algorithm  Confusion 취약점 설명
- 알고리즘 컨퓨전(혼란) 공격은 키 컨퓨전 공격이라고도 불린다. 
- JWT의 서명을 검증하는 알고리즘을 개발자가 예측하지 못한 알고리즘으로 지정하는 공격이다. 

## 대칭키 vs 비대칭키 알고리즘 (Symmetric vs asymmetric algorithms)
- JWT는 다양한 방식으로 서명될 수 있다. 예를 들면 HS256(HMAC + SHA-256)는 대칭키(symmetric key)를 사용한다. 
- 이는 서버가 토큰의 서명과 검증에 동일한 키를 사용한다는 것을 의미한다. 
- 이 키는 패스워드처럼 안전하게 감추어두어야 한다는 것이 명백하다. 
- RS256(RSA + SHA-256)같은 것은 비대칭키 쌍(asymmetric key pair)를 사용한다. 
- 개인키는 서버가 서명을 하는데 사용하고, 공개키는 제삼자가 서버의 서명을 검증하는데 사용한다. 
- 개인키는 서버가 안전하게 보관하고, 공개키는 누구나 볼 수 있도록 공유해서 서버가 발행한 토큰의 서명을 검증할 수 있도록 한다.  

## 어떻게 알고리즘 컨퓨전 취약점이 일어나는가? (How do algorithm confusion vulnerabilities arise?)
- 알고리즘 컨퓨전은 종종 JWT라이브러리의 구현에 결함이 있을 때 발생한다. 
- 실제의 검증 프로세스는 사용되는 알고리즘에 따라 다르지만, 많은 라이브러리는 서명을 검증하는데 하나의 방법을 사용한다. 
- 이 것들은 토큰 헤더의 `alg`파라메터에 의존한다. 
- 다음은 간단한 슈도 코드이다. 

```java
function verify(token, secretOrPublicKey){
    algorithm = token.getAlgHeader();
    if(algorithm == "RS256"){
        // Use the provided key as an RSA public key
    } else if (algorithm == "HS256"){
        // Use the provided key as an HMAC secret key
    }
}
```

문제는 개발자가 서명된 JWT 를 처리하는데 비대칭키 알고리즘인 RS256만을 사용할 것으로 추정하는 경우이다. 이 결함이 있는 추정때문에, 다음처럼 공개키를 서명을 검증하는 메서드에 전달하게 된다. 

```java
publicKey = <public-key-of-server>;
token = request.getCookie("session");
verify(token, publicKey);
```

이 경우에, 서버는 대칭키를 사용하는 HS256로 서명된 토큰이어도 공개키를 사용해 검증하게 된다. 즉, 공격자는 공개키를 사용해 HS256 알고리즘으로 토큰을 서명하고 서버는 동일한 공개키로 서명을 검증하게 된다. 따라서 JWT검증을 통과할 수 있다! 

## Burp Suite를 이용해서 알고리즘 컨퓨전 공격 수행하기

### Step 1 - 서버의 공개키 얻어내기
서버는 공개키를 JSON Web Key(JWK) 오브젝트로 해서 `/jwks.json`이나 `/.well-known/jwks.json`과 같은 잘 알려진 엔드포인트로 공개하는 경우가 있다. 이는 `keys`라고 하는 배열에 담겨있다. 예를 들면 다음과 같은 형식이다. 

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

- 혹시 공개키가 공개되어 있지 않아도, 이미 존재하는 토큰으로부터 추출하는 방법도 있다. (이건, 다음 문제에서 다룬다.)


### Step 2 - 공개키를 적절한 포맷으로 변환(Convert the public key to a suitable format)
서버가 JWK 로 공개키를 공개하고 있더라도, 서버는 공개키를 로컬 파일시스템이나 데이터베이스에 저장하고 있으므로 저장시에는 다른 포맷으로 저장하고 있을 수도 있다. 공격을 성공시키기 위해서는 JWT를 서명하는데 사용하는 키가 서버에 저장된 로컬 카피와 완전히 동일해야 한다. 동일한 포맷이어야 할 뿐 아니라, 모든 바이트까지 정확히 일치해야 한다. 

예를 들어, X.509 PEM 포맷의 키가 필요하다고 하자. JWK를 Burp의 JWT Editor 탭에서 PEM으로 변환할 수 있다. 

1. JWT Editor Keys에서 New RSA Key를 누른다. 다이얼로그에 얻어낸 JWK를 붙여넣기 한다. 
2. PEM 라디오 버튼을 선택하고 결과를 카피한다. 
3. Decoder탭에서 PEM을 Base64인코딩한다. 
4. 다시 JWT Editor Keys탭으로 돌아가서 New Symmetric Key를 클릭한다. 
5. 다이얼로그에서 Generate 버튼을 눌러서 새로운 키를 JWK 포맷으로 생성한다. 
6. `k`파라메터를 Base64인코딩된 PEM키로 대체한다. 
7. 키를 보존한다. 

### Step 3 - JWT변조(Modify your JWT)
`alg`헤더를 `HS256`로 바꾼다. 그리고 나머지 페이로드도 입맛에 맞게 바꾼다. 

### Step 4 - Sign the JWT using the public key
Sign the token 버튼을 눌러 RSA 공개키를 사용해서 HS256알고리즘으로 서명한다. 


# 문제 설명
이 랩은 세션을 처리하기 위해 JWT 기반 메커니즘을 사용한다. 서버는 서명 및 서명 확인을 위해 강력한 RSA 키 페어를 사용한다. 그러나 구현에 실수가 있기 때문에 알고리즘 컨퓨전 공격에 취약하다. 

랩을 풀려면 먼저 알려진 엔드포인트를 통해 서버의 공개키를 얻어낸다. 이 키를 사용하여 변조한 세션토큰을 서명하고, /admin 관리자 패널에 접근한 후 carlos 유저를 삭제하라.

wiener:peter 크레덴셜로 로그인할 수 있다. 

```
This lab uses a JWT-based mechanism for handling sessions. It uses a robust RSA key pair to sign and verify tokens. However, due to implementation flaws, this mechanism is vulnerable to algorithm confusion attacks.

To solve the lab, first obtain the server's public key. This is exposed via a standard endpoint. Use this key to sign a modified session token that gives you access to the admin panel at /admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter
```

# 풀이
## 정상적인 크레덴셜로 로그인 
- 주어진 크레덴셜로 로그인해서 일단 정상적인 JWT을 얻어낸다. 

## JWT의 sub 및 HTTP 요청경로 변경
- JSON Web Token탭에서 Payload의 sub를 administrator로 바꾼다. 
- HTTP요청의 경로를 /admin으로 바꾼다. 

## 서버의 공개키 얻어내기 
- 딱히 공개키를 얻기위한 힌트는 없는 것 같다. 
- 일단 서버 패스 `/jwks.json`에 접근해본다. 
- 바로 확인할 수 있었다! 

```json
{"keys":[{"kty":"RSA","e":"AQAB","use":"sig","kid":"ec57c1b1-0369-44df-9e30-bae7a68e5348","alg":"RS256","n":"oWW2pEY5-Y_CzbOyB1D_n1kzhmKSVw4ui3LGMq9wIy08F691w7YsX0Tw7kKl4pY1Ig5a0hSSXU_jHwRxm0cAyz5LQ14svmosfc_eZdnD-D7lXE3nzgSgDQdIgxx-I4NCfG05r4SlfLEHQkJO3h4CvyhUbDvDoklj6WNevqhasy5Enpx5VUjSAwJSLNcOaOtuLjP2geuJvTSVZ_SSShstsJM5G6mICfpWvnj6GKx5jJ8IgLr2QfXlf6W3R9dupOkrqC-lOdJe4eG-m5EwjMyv9mAcEkt5up_DNpBPuNHgzu_cWksHS_hEDqrFim0tsQTy-gnWYL4B1oAD1Iw2xNpb2w"}]}
```

## 공개키를 적절한 포맷으로 변환 
JWT Editor Keys 메뉴에서 New RSA Key를 누른다. 다이얼로그에 위의 과정에서 얻어낸 JWK(공개키)를 붙여넣기 한다. 

PEM 라디오 버튼을 선택하고 결과를 클립보드에 카피(Ctrl +c)해둔다. 

![공개키를 PEM형식으로 변환](/images/burp-academy-jwt-7-1.png)


 Decoder탭에서 PEM을 Base64인코딩한다. 

![PEM을 Base64 인코딩](/images/burp-academy-jwt-7-2.png)

```
LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFvV1cycEVZNStZL0N6Yk95QjFELwpuMWt6aG1LU1Z3NHVpM0xHTXE5d0l5MDhGNjkxdzdZc1gwVHc3a0tsNHBZMUlnNWEwaFNTWFUvakh3UnhtMGNBCnl6NUxRMTRzdm1vc2ZjL2VaZG5EK0Q3bFhFM256Z1NnRFFkSWd4eCtJNE5DZkcwNXI0U2xmTEVIUWtKTzNoNEMKdnloVWJEdkRva2xqNldOZXZxaGFzeTVFbnB4NVZValNBd0pTTE5jT2FPdHVMalAyZ2V1SnZUU1ZaL1NTU2hzdApzSk01RzZtSUNmcFd2bmo2R0t4NWpKOElnTHIyUWZYbGY2VzNSOWR1cE9rcnFDK2xPZEplNGVHK201RXdqTXl2CjltQWNFa3Q1dXAvRE5wQlB1TkhnenUvY1drc0hTL2hFRHFyRmltMHRzUVR5K2duV1lMNEIxb0FEMUl3MnhOcGIKMndJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==
```

다시 JWT Editor Keys탭으로 돌아가서 New Symmetric Key 를 클릭한다. 얻어낸 공개키를 대칭키로 사용하도록 하기 위해 필요한 과정이다.

다이얼로그에서 Generate 버튼을 눌러서 새로운 키를 JWK 포맷으로 생성한다. 

![새로운 대칭키 생성](/images/burp-academy-jwt-7-3.png)


`k`파라메터를 Base64인코딩된 PEM키로 대체한 후 OK를 누른다. 

![키 대체](/images/burp-academy-jwt-7-4.png)



## alg헤더 알고리즘 변경 
Repeater의 JSON Web Token탭에서 JWS 헤더의 알고리즘을 `RS256`에서 `HS256`로 바꾼다.


## 재서명 
Sign 버튼을 눌러서 재서명한다. 다이얼로그에서 위의 과정에서 만든 키를 선택해서 재서명한다. 

![재서명](/images/burp-academy-jwt-7-5.png)

## 변조된 요청을 전송 
HTTP 요청을 전송하면 200응답이 확인된다. 


## Carlos유저 삭제 
요청경로를 admin에서 carlos유저를 삭제하는 경로 /admin/delete?username=carlos로 변경후 다시 한번 요청을 보내면 랩이 풀린다. 

![풀이성공](/images/burp-academy-jwt-7-success.png)
