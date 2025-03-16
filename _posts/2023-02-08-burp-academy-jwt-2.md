---
layout: post
title: "Burp Academy-JWT 두번째 문제:JWT authentication bypass via flawed signature verification"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, JWT취약점]
toc: true
last_modified_at: 2025-03-07 05:55:00 +0900
---

# 개요
- JWT(JSON Web Token) 취약점 두번째 문제이다. 
- JWT 취약점 설명 주소: https://portswigger.net/web-security/jwt
- 문제 주소: https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification
- 난이도: APPRENTICE (쉬움)


# 취약점 개요: 서명이 없는 토큰 수락(Accepting tokens with no signature)
JWT 헤더에는 `alg`파라메터가 포함되어 있다. 이는 서버에 토큰에 서명하는 데 사용된 알고리즘을 알려주고, 따라서 서명을 검증할 때 사용해야 하는 알고리즘을 알려준다.  

```
{
    "alg": "HS256",
    "typ": "JWT"
}
```

이는 본질적으로 결함이 있는데, 서버는 토큰에서 사용자가 제어할 수 있는 입력을 암묵적으로 신뢰할 수밖에 없기 때문이다. 다시 말해, 공격자는 서버가 토큰이 신뢰할 수 있는지 확인하는 방법에 직접적으로 영향을 미칠 수 있다.

JWT는 다양한 알고리즘을 사용하여 서명할 수 있지만 서명하지 않은 채로 둘 수도 있다. 이 경우 `alg` 파라메터는 none이 되고, 이는 소위 "unsecured JWT"로 불린다. 이것의 명백한 위험 때문에 서버는 일반적으로 서명이 없는 토큰을 거부한다. 그러나 이러한 종류의 필터링은 문자열 구문 분석에 의존하기 때문에 대소문자 혼합 사용 및 예상치 못한 인코딩과 같은 고전적인 난독화 기술을 사용하여 이러한 필터를 우회할 수 있는 경우가 있다.

주의: 토큰이 서명되지 않은 상태라도 페이로드 파트는 여전히 마지막 점(.)으로 끝나야 한다. 

# 문제 분석 
- 이 랩은 JWT 기반으로 세션을 처리한다. 서버는 서명되지 않는 JWT도 처리하도록 안전하지 못하게 설정되어 있다. 
- 랩을 풀려면 세션토큰을 변조하여 관리자 패널(/admin)에 접근하여 carlos유저를 삭제하면 된다.
- wiener:peter 크레덴셜을 사용하여 로그인 가능하다. 

```
This lab uses a JWT-based mechanism for handling sessions. The server is insecurely configured to accept unsigned JWTs.

To solve the lab, modify your session token to gain access to the admin panel at /admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter
```
 

# 풀이 
1. 로그인 후에 발급받은 JWT토큰을 변조했다. 요청경로는 /admin으로 하고, alg는 공백으로, sub를 administrator로 만든 후 요청을 보내보았다. 결과는 401 Unauthorized였다. 단순히 `alg` 필드를 공백으로 하는 것만으로는 부족한 것 같다. 

![1차시도](/images/burp-academy-jwt-2-1.png)

2. Note 부분이 힌트일 수도 있을 것 같다. 아예 서명부분을 지워보자. 서명부분은 점(.)으로 구분되는 JWT의 세번째 부분이다. 이 부분을 삭제하고 다시 요청을 보내 보았다. 결과는 200 응답이었다!

※ 나중에 해답을 보니, `alg`필드를 `none` 으로 설정하는 것이 의도된 답이었던 것 같다. 

![2차시도](/images/burp-academy-jwt-2-2.png)

3. 200응답의 페이지에 carlos 유저를 삭제하는 링크가 보인다. HTTP 요청의 경로를 유저 삭제 경로로 변경한 후 다시 요청을 보낸다. 302 응답이 돌아온다. 

![2차시도](/images/burp-academy-jwt-2-3.png)

4. 랩이 풀렸다. 

![성공](/images/burp-academy-jwt-2-success.png)
