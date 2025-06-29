---
layout: post
title: "Burp Academy-JWT 여섯번째 문제:Injecting self-signed JWTs via the kid parameter"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, JWT취약점]
toc: true
last_modified_at: 2025-03-31 21:55:00 +0900
---

# 개요
- JWT(JSON Web Token) 취약점 여섯번째 문제이다. 
- `kid`파라메터를 통해 자신이 서명한 JWT를 사용해서 인증을 우회하는 문제이다. 
- JWT 취약점 설명 주소: https://portswigger.net/web-security/jwt
- 문제 주소: https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal
- 난이도: PRACTITIONER (중간)

# `kid` 파라메터를 통해 자신이 서명한 JWT를 삽입하기 (Injecting self-signed JWTs via the kid parameter)
서버는 JWT뿐만 아니라 여러 종류의 데이터에 서명하기 위해 여러 종류의 암호키를 사용할 수 있다. 이 이유때문에 JWT에는 `kid`(Key ID)파라메터를 포함하는 경우가 있다. 이 파라메터는 서버에게 서명을 검증하기해 어떤 키를 사용하면 되는지 알려주는 역할을 한다. 
검증용 키는 종종 JWK Set으로 저장된다. 이 경우, 서버는 `kid`에 지정된 값과 동일한 JWK를 사용한다. 그러나, JWS 스펙에는 이 ID의 구조에 대한 명확한 정의가 없다. 그냥 개발자가 지정할 수 있는 문자열일 뿐이다. 예를들면, `kid`파라메터는 데이터베이스의 엔트리를 지정할 수도 있고, 파일의 이름을 지정할 수도 있다. 
만약 `kid`파라메터가 `directory traversal`에 취약하면, 공격자는 서버에게 서버상에 존재하는 임의 파일을 서명검증용 키로 사용하도록 만들 수도 있다. 

```json
{
    "kid": "../../path/to/file",
    "typ": "JWT",
    "alg": "HS256",
    "k": "asGsADas3421-dfh9DGN-AFDFDbasfd8-anfjkvc"
}
```

이 것은 서명검증에 대칭키를 사용하는 경우에 특히 위험하다. 공격자가 서버의 예측할 수 있는 정적파일을 서명 검증키로 사용하도록 만들 수 있기 때문이다. 이 경우, 이론적으로 아무 파일이나 가능하지만, 가장 간단한 방법은 어느 리눅스 시스템에나 존재하는 `/dev/null`을 사용하는 것이다. 이 것은 빈 파일이기 때문에, 읽으면 공백 문자열을 리턴한다. 그러므로 **토큰을 공백 문자열로 서명하면 정당한 서명(valid signature)이 만들어진다.** 

# 문제 개요 
이 랩은 세션을 처리하기 위해 JWT 기반 메커니즘을 사용한다. 서명을 확인하기 위해 서버는 JWT 헤더의 kid 매개변수를 사용하여 파일 시스템에서 관련 키를 가져온다.

랩을 풀려면 /admin에서 관리자 패널에 액세스할 수 있는 JWT를 위조한 다음 사용자 carlos를 삭제하라.

wiener:peter 크레덴셜로 로그인할 수 있다. 

참고   
JWT Editor 확장 프로그램을 사용하는 경우 빈 문자열을 사용하여 토큰에 서명할 수 없다. 그러나 확장 프로그램의 버그로 인해 Base64로 인코딩된 null 바이트를 사용하여 이를 해결할 수 있다.

```
This lab uses a JWT-based mechanism for handling sessions. In order to verify the signature, the server uses the kid parameter in JWT header to fetch the relevant key from its filesystem.

To solve the lab, forge a JWT that gives you access to the admin panel at /admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter

Note
If you're using the JWT Editor extension, note that this doesn't let you sign tokens using an empty string. However, due to a bug in the extension, you can get around this by using a Base64-encoded null byte.
```

# 풀이  
## 정상적인 크레덴셜로 로그인 
- 주어진 크레덴셜로 로그인해서 일단 정상적인 JWT을 얻어낸다. 

## 변조하기 
### JWT의 sub 및 HTTP 요청경로 변경
- JSON Web Token탭에서 Payload의 sub를 administrator로 바꾼다. 
- HTTP요청의 경로를 /admin으로 바꾼다. 

### kid 변경 
- JSON Web Token 탭에서 토큰의 헤더를 보면 다음과 같이 생겼다. kid에 어떤 키를 사용할지 ID가 지정되어 있다. 

```json
{
    "kid": "bc35f634-2bed-4fa5-a09a-afedce91a6f0",
    "alg": "HS256"
}
```

- kid를 /dev/null로 바꾼다. 

```json
{
    "kid": "/dev/null",
    "alg": "HS256"
}
```

### null바이트 키 추가  
null바이트키를 추가한다. 어떻게 추가하는가?
JWT Editor Keys 탭에서 New Symmetric Key 버튼을 누른다. 일단 Generate 버튼을 눌러서 키를 생성한뒤 kid 값을 다음과 같이 null바이트를 Base64으로 인코딩한 값 `AA==`로 변경한다. 

![null바이트키 추가하기](/images/jwt-symmetric-key-with-null-byte-base64.png)


### 새롭게 서명
- Sign 버튼을 눌러 토큰에 재서명한다. 이 때 위에서 만든 null바이트 키를 선택한다. Header Options는 Don't modify header를 선택한다. 

![null바이트키로 서명하기](/images/jwt-sign-with-null-byte-base64.png)

이 상태로 요청을 보내본다. 안된다. 401 Unauthorized 응답이 돌아왔다. 어디가 잘못된 걸까? 모르겠다... 정답을 봤다. 

### 정답을 확인
정답에는 kid값이 `/dev/null` 이 아니라 `../../../../../../../dev/null` 로 되어있었다.  즉, 다음과 같은 형태이다. 

```json
{
    "kid": "../../../../../../../dev/null",
    "alg": "HS256"
}
```

이 상태로 다시 null바이트키로 서명해서 요청을 보내니 200응답이 확인됐다. 이 상태에서 요청경로만 carlos유저를 삭제하는 경로(/admin/delete?username=carlos)로 바꿔서 다시 요청을 보내면 성공했다는 메세지가 출력된다. 

![성공](/images/burp-academy-jwt-6-success.png)


## 궁금점 및 중요한 포인트를 다시 확인
그런데 반드시 `../../../../../../../dev/null`여야만 할까? 즉, `../`가 정확히 7개 붙은 모습이여야만 할까?    
`../../../../../../../dev/null`에서 `../`를 삭제하고 테스트해도 성공했다. 즉, 정확히 `../`가 몇 개있어야 된다는 게 아니라 충분한 양이 있으면 성공하는 것 같다.    

좀 더 테스트해보니 `../`는 반드시 3개는 필요했다. 3개이상이면 서명 검증을 통과했다. 추측컨대 kid를 `/dev/null`로 했을 경우는 상대경로 인식해서 웹 앱의 현재경로의 `/dev/null`, 즉, `./dev/null`을 찾는 것으로 인식하는 것 같다. `/dev/null`은 리눅스 시스템에서 루트 경로에 위치한다. 루트 경로가 아닌 곳에서 `/dev/null`에 접근하면 다음과 같이 그런 것 없다는 메세지가 출력된다. 

```sh
$cat ./dev/null
cat: ./dev/null: No such file or directory
```

리눅스 시스템에서 `../`는 아무리 많아도 결국에는 최상위 디렉토리까지만 이동할 수 있다. `../`는 서버의 웹 앱의 경로에서 부터 시작해서 상대경로로 최상위 경로까지 이동하기 위한 방법이라고 생각된다. `../`가 적절히 많으면 아무리 웹 앱 경로의 depth가 어느정도 깊어도 결국에는 최상위 경로까지 도달한다(BOF의 Nop썰매와 비슷하게 반드시 공격지점으로 이동시키기위한 수단같다).





