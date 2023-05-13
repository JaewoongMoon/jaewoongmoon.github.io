---
layout: post
title: "Burp Academy-OpenID Connect"
categories: [Burp Academy, OAuth, OpenID Connect]
tags: [Burp Academy, OAuth, OpenID Connect]
toc: true
---

# 개요
- Burp Academy의 [Open ID Connect](https://portswigger.net/web-security/oauth/openid)의 내용을 대략 번역한 페이지이다. 

# OpenID Connect란?
- OAuth 프로토콜을 확장한 것이다. 
- OAuth위에서 추가로 식별(identify)과 인증(authentication) 레이어를 제공해준다. 
- OAuth와 비교해서 더 좋은 인증 서포트 기능이 있다. 
- OAuth는 처음에는 인증을 위해서 디자인된 것이 아니었다. 원래는 어플리케이션들 사이에서 특정 리소스에 대한 인가(authorization) 권한을 위임하기 위한 것이었다. 
- 그러나 많은 웹사이트들이 OAuth를 커스터마이징해서 인증 메커니즘으로 사용하기 시작했다. 
- 웹사이트는 사용자의 기본 데이터에 대한 읽기 액세스 권한을 요청하고, 만약 이 요청이 승인되면, 유저가 OAuth 서비스측에서 정상적으로 인증되었다고 가정한다. 
- 이 OAuth 인증은 이상적인 상황과는 거리가 멀다. 
- 우선 클라이언트 애플리케이션은 사용자가 언제, 어디서, 어떻게 인증되었는지 알 수 있는 방법이 없다. 이러한 각 구현은 OAuth 클라이언트 측에서 구현해야했다. 이 목적을 위해 사용자 데이터를 요청하는 표준 방법도 없었다. OAuth를 적절하게 지원하려면 클라이언트 애플리케이션은 각 OAuth 서비스 공급자에 대해 서로 다른 엔드포인트, 고유한 범위 세트 등을 가진 별도의 OAuth 메커니즘을 구성해야 했다. 
- OpenID Connect는 표준화된 ID 관련 기능을 추가하여 OAuth를 통한 인증이 보다 안정적이고 동일한 방식으로 작동하도록 함으로써 이러한 많은 문제를 해결한다. 

# OpenID Connect는 어떻게 동작하는가?
- OpenID Connect 는 일반적인 OAuth 플로우와 연동되어 동작한다. 
- 클라이언트 애플리케이션의 관점에서 주요한 차이점은 모든 공급자에 대해 동일한, 표준화된 추가 스코프들이 있다는 점과 추가 응답 유형인 `id_token`이 있다는 점이다. 


# OpenID Connect roles
OpenID Connect에서 제공하는 롤(role)은 본질적으로 OAuth와 동일하다. 차이점은 사용하는 용어가 좀 다르다는 점이다. 
- Relying party: 유저에 대한 인증을 요구하는 어플리케이션. OAuth에서 클라이언트 어플리케이션과 동일하다. 
- End user: 인증되는 유저. OAuth의 리소스 오너(소유자)와 동일하다. 
- OpenID provider: OpenID Connect를 구성하고 제공하는 서비스 측

# OpenID Connect claims and scopes
- 클레임(claim)이란 리소스 서버의 유저의 정보를 나타내는 key:value페어를 말한다. ex) "family_name":"Montoya"
- 제공자마다 서로 다른 scope가 있는 OAuth와는 다르게, OpenID Connect에서는 몇 가지 스탠다드 scope가 정의되어 있다. 
- OpenID Connect를 사용하려면 클라이언트 어플리케이션은 `openid`라는 scope를 인가요청(Authz request)에 포함시켜야 한다. 그리고 다음의 스탠다드 scope 중에서 하나이상을 포함시킬 수 있다. 

OpenID Connect standard scope
- profile
- email
- address
- phone 

예를들면 `openid profile` scope는 클라이언트 어플리케이션에게 family_name, given_name, birth_date 등의 유저 정보에 대한 읽기 요청을 허용한다. 

# ID token
- OpenID Connect에서 추가된 중요한 것들중 `id_token` 응답 타입(response type)이 있다. 
- 이 것은 JWS(JSON Web signature)로 서명된 JWT(JSON web token)을 리턴한다. 
- JWT의 페이로드부분에는 요청의 scope에 해당되는 정보의 목록이 포함되어 있다. 
- 그리고 유저가 어떻게, 언제 OAuth 서비스로부터 인증되었는지에 대한 정보도 포함되어 있다. 
- 클라이언트 어플리케이션은 이 정보를 보고 유저가 적절히 인증되었는지를 판단할 수 있다. 
- `id_token`을 사용함으로써 얻는 주된 이익은 클라이언트 어플리케이션과 OAuth서비스 사이의 요청수를 줄여준다는 점이다. 
- 따라서 더 좋은 퍼포먼스가 가능하다(기본적인 OAuth에서는 억세스 토큰을 얻은 후에 유저 데이터를 따로 따로 요청하게 되지만, ID 토큰은 이런 데이터를 이미 포함하고 있다).
- 데이터의 완전성(integrity)은, 기본적인 OAuth에서는 신뢰할 수 있는 채널에 의존하지만 ID token에서는 JWT 암호 서명에 의존한다. 
- 이 이유때문에, ID token은 중간자 공격(man-in-the-middle attacks)에 대해서도 안전하다. 
- 그러나 서명 검증에 사용하는 키가 /.well-known/jwks.json 등과 같이 알려진 경로로 공개되므로 여전히 몇몇 공격은 가능하다. 

유의점
- OAuth에서는 여러 종류의 응답 타입(response type)을 지원하기 때문에, 다음과 같이 클라이언트 어플리케이션이 `id_token ` 타입이 함께 기본적으로 OAuth 에서 제공하는 response type을 함께 사용하는 것은 전혀 문제가 없다. 

```
response_type=id_token token
response_type=id_token code
```

# OpenID Connect를 사용하고 있는지 알아보는 방법
- 가장 간단한 방법은 authorization 요청을 관찰하는 것이다. `openid` 스코프가 포함되어 있으면 OpenID Connect를 사용한다고 볼 수 있다. 
- 관찰해도 알 수 없을 때는, 직접 scope 파라메터에 `openid` 를 추가해보거나 response_type 파라테너를 `id_token`으로 해보거나 하는 등으로 테스트할 수 있다. 
- 혹은 OAuth 제공자의 문서를 확인하고 알려진 엔드포인트로 접속해보는 방법이 있다. `/.well-known/openid-configuration` 등이다. 

# OpenID Connect 취약점
- OAuth와 비교해서 더 엄격한 구현을 요구하기 때문에 OpenID Connect 자체에는 구현 미스로 인한 취약점이 발생할 여지가 적다. 
- 그러나 OpenID Connect는 OAuth의 상위 레이어이기 때문에 OAuth 구현 미스로 인한 취약점은 여전히 발생할 수 있다. 

# Unprotected dynamic client registration
- 임의의 유저가 마음대로(동적으로) 클라이언트를 등록할 수 있으면 보안상 문제가 될 수 있다. 
- 특히 별도의 인증없이도(예를들면, 인증 헤더의 토큰값 검증없이도) 등록할 수 있으면 더욱 문제가 된다. 
- 예를들면 다음과 같은 HTTP 요청으로 클라이언트가 등록된다. 

```htt
POST /openid/register HTTP/1.1
Content-Type: application/json
Accept: application/json
Host: oauth-authorization-server.com
Authorization: Bearer ab12cd34ef56gh89

{
    "application_type": "web",
    "redirect_uris": [
        "https://client-app.com/callback",
        "https://client-app.com/callback2"
        ],
    "client_name": "My Application",
    "logo_uri": "https://client-app.com/logo.png",
    "token_endpoint_auth_method": "client_secret_basic",
    "jwks_uri": "https://client-app.com/my_public_keys.jwks",
    "userinfo_encrypted_response_alg": "RSA1_5",
    "userinfo_encrypted_response_enc": "A128CBC-HS256",
    …
}
```


이 부분에 대한 문제는[여기]({% post_url 2023-05-12-burp-academy-oauth-5 %})에서 이어서 푼다. 