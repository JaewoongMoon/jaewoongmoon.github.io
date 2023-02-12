---
layout: post
title: "Burp Academy-JWT 두번째 문제:JWT authentication bypass via flawed signature verification"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, JWT취약점]
toc: true
---


# 개요
- JWT(JSON Web Token) 취약점 두번째 문제이다. 
- JWT 취약점 설명 주소: https://portswigger.net/web-security/jwt
- 문제 주소: https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification
- 난이도: APPRENTICE (쉬움)


# 취약점 개요: Accepting tokens with no signature
```
Among other things, the JWT header contains an alg parameter. This tells the server which algorithm was used to sign the token and, therefore, which algorithm it needs to use when verifying the signature.

{
    "alg": "HS256",
    "typ": "JWT"
}

This is inherently flawed because the server has no option but to implicitly trust user-controllable input from the token which, at this point, hasn't been verified at all. In other words, an attacker can directly influence how the server checks whether the token is trustworthy.

JWTs can be signed using a range of different algorithms, but can also be left unsigned. In this case, the alg parameter is set to none, which indicates a so-called "unsecured JWT". Due to the obvious dangers of this, servers usually reject tokens with no signature. However, as this kind of filtering relies on string parsing, you can sometimes bypass these filters using classic obfuscation techniques, such as mixed capitalization and unexpected encodings.

Note
Even if the token is unsigned, the payload part must still be terminated with a trailing dot.
```

- JWT 헤더에 있는 `alg` 필드는 서버에게 어떤 알고리즘이 토큰을 서명하는데 사용되었는지를 알려준다. 
- 따라서 서버는 그 알고리즘을 이용해서 서명을 검증하게 된다. 
- 이 것은 선천적으로 결함이 있다. 왜나하면 서버는 (유저가 컨트롤가능한) 토큰 헤더의 정보를 믿을 수 밖에 없기 때문이다. 
- 다른말로 하면, 공격자는 토큰이 신뢰할 수 있는지 여부와 관계없이 서버가 토큰을 체크하는 부분에 영향을 줄 수 있다. 
- JWT는 다양한 알고리즘으로 서명될 수 있지만, 서명하지 않은 채로 둘 수도 있다. (이 경우에는 `alg` 필드를 none으로 둔다. 이 것을 "unsecured JWT"라고 부른다.)
- unsecured JWT는 보안상 서버측에서 거절하는 것이 당연하지만, 문자열 필터링 로직에 버그가 있다면 우회할 수도 있다. 
- 우회하는 테크닉은 대소문자 섞기, 예측하지 못한 인코딩 사용하기 등 클래식한 테크닉을 사용할 수 있다. 
- Note: 토큰이 서명되지 않은 상태라도 페이로드 파트는 여전히 마지막 점(.)으로 끝나야 한다. 

# 문제 분석 
```
This lab uses a JWT-based mechanism for handling sessions. The server is insecurely configured to accept unsigned JWTs.

To solve the lab, modify your session token to gain access to the admin panel at /admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter
```

- 첫번째 문제와 마찬가지로, /admin에 접근할 수 있는 세션토큰을 만들어서 관리자 기능을 이용해 carlos라는 유저를 삭제하면 된다. 
- JWT 헤더의 `alg` 필드를 변조해보자. 

# 풀이 
## 1차 시도 
- 로그인 후에 발급받은 JWT토큰을 변조했다. 요청경로는 /admin으로 하고, alg는 공백으로, sub를 administrator로 만든 후 요청을 보내보았다. 
- 결과는 401 Unauthorized였다. 
- 단순히 alg 를 공백으로 하는 것만으로는 부족한 것 같다. 

![1차시도](/images/burp-academy-jwt-2-1.png)

## 2차 시도 
- Note 부분이 힌트일 수도 있을 것 같다. 
- 아예 서명부분을 지워보자. 서명부분은 점(.)으로 구분되는 JWT의 세번째 부분이다. 이 부분을 삭제하고 다시 요청을 보내 보았다. 
- 결과는 200 응답이었다!

![2차시도](/images/burp-academy-jwt-2-2.png)

- 200응답의 페이지에 calors 유저를 삭제하는 링크가 보인다. HTTP 요청의 경로를 유저 삭제 경로로 변경한 후 다시 요청을 보낸다. 
- 302 응답이 돌아온다. 

![2차시도](/images/burp-academy-jwt-2-2.png)

- 문제 웹 페이지를 보면 성공했다는 메세지가 보인다. 
![성공](/images/burp-academy-jwt-2-success.png)
