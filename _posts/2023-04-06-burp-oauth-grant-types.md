---
layout: post
title: "Burp Academy-OAuth grant types"
categories: [Burp Academy]
tags: [Burp Academy, OAuth]
toc: true
---

# 개요
- Burp Academy의 [OAuth grant type 페이지](https://portswigger.net/web-security/oauth/grant-types)의 내용을 대략 번역한 페이지이다. 
- OAuth의 대략적인 흐름을 간단히 이해하기에는 매우 좋은 자료라고 생각된다. 

# OAuth grant type이란?
OAuth grant type은  OAuth 프로세스를 구성하는 각 스텝을 결정한다. grant type은 또한 클라이언트 어플리케이션이 각 스테이지에서 OAuth 서비스와 어떻게 통신하는지에도 영향을 미친다. 이는 어떻게 액세스 토큰이 전달되는가도 포함한다. 이 이유때문에, grant type은 `OAuth flows`라고도 불린다. 

OAuth 서비스는 클라이언트 어플리케이션이 특정 OAuth 플로우를 시작하기 전에 반드시 특정 grant type을 지원하도록 구성되어 있어야한다.   

OAuth에는 여러가지 종류의 grant type이 있고, 각 grant type 별로 복잡하고 다양한 레벨의 보안 심사숙고 사항이 있다. 여기서는 가장 일반적인 `authorization code`와 `implicit` 2종류의 grant type에 집중한다. 

# OAuth scopes 
어떤 OAuth grant type이라고 해도 클라이언트 어플리케이션은 어떤 데이터에 접근하고 싶은지와 어떤 업무를 수행(operation)하고 싶은지를 명시해야 하는 것은 동일하다. 이 것은 인가 요청에 `scope` 파라메터를 보내는 것으로 수행된다.   

기본적인 OAuth에서는 OAuth 서비스별로 scope가 다르다. scope는 단순한 문자열이기 때문에 포맷은 OAuth 프로바이더별로 매우 다양하다. 어떤 곳은 REST API 엔드포인트처럼 URI 전체를 사용하는 곳도 있다.   

```
scope=contacts
scope=contacts.read
scope=contact-list-r
scope=https://oauth-authorization-server.com/auth/scopes/user/contacts.readonly
```

그러나, OAuth가 인증(authentication)으로 사용될 때 표준화된 OpenID Connect socpe가 종종 대신 사용된다. 예를 들면, `openid profile`는 클라이언트 어플리케이션에게 미리 정의된 사용자의 기본 정보(이메일 주소, 유저이름 등) 에 관한 읽기 권한을 주기 위한 scope이다.

# Authorization code grant type

![Authorization code grant type](/images/burp-academy-oauth-grant-type-authorization-code.png)
(출처: https://portswigger.net/web-security/oauth/grant-types)

흐름을 간단하게 설명하면, 클라이언트 프로그램과 OAuth 서비스는 몇가지 브라우저 기반의 HTTP요청을 이용해 OAuth 플로우를 시작하기 위해 리다이렉트를 사용한다. 유저에게 데이터의 접근 요청에 대해 동의하는지 물어본다. 만약 동의하면, 클라이언트 어플리케이션은 인가코드(authorization code)를 얻는다. 클라이언트 어플리케이션은 이 것을 OAuth 서비스에게 보내서 액세스 토큰으로 바꾸고, 이 토큰을 이용해서 유저데이터를 얻어오는 API를 호출한다.   

모든 통신은 미리 정의된 서버 대 서버의 code/token 교환으로 이루어지고, 따라서 유저에게는 보이지 않는다. 이 서버 대 서버 채널은 클라이언트 어플리케이션의 OAuth 서비스에 등록할 때 만들어진다. 이 시점에 `client_secret`이 만들어진다. 이 것은 서버 대 서버 통신을 할 때 사용하게 된다. 

가장 민감한 데이터(액세스 토큰과 유저 데이터) 브라우저를 통해 이루어지지 않으므로, 논쟁의 여지는 있지만 가장 안전한 것으로 취급된다. 서버 사이드 어플리케이션은 이상적으로는 가능한 경우 항상 이 grant type을 사용해야 한다. 

## 1. Authorization request
클라이언트 어플리케이션이 특정 유저데이터에 접근하는 것을 허용해달라는 요청을 OAuth 서비스의 `/authorization`엔드포인트로 보낸다. 엔드포인트명은 프로바이더에 따라 달라질 수 있다. burp 랩에서는 `/auth`엔드포인트를 사용한다. 진단 엔지니어는 요청의 파라메터를 보고 이 것이 어떤 요청이구나 하는 것을 읽어낼 능력이 있어야 한다. 

```http
GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=code&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
Host: oauth-authorization-server.com
```

요청은 다음의 몇 가지 중요한 파라메터를 포함한다. 

- client_id  
클라이언트 어플리케이션을 구별하는 유일한 값이다. 필수로 지정해야 한다. 이 값은 클라이언트 어플리케이션 OAuth 서비스에 등록할 때 만들어진다. 

- redirect_uri    
클라이언트 어플리케이션에게 인가코드(authorization code)를 보내기 위해 유저 브라우저가 어디로 리다이렉트되어야 하는지 나타내는 URI이다. callback URI 또는 callback endpoint로도 불린다. 많은 OAuth 공격은 이 파라메터의 검증(validation) 결함을 공격하는 것을 기본으로 한다. 

- response_type    
클라이언트 어플리케이션이 어떤 응답을 기대하는지, 즉 어떤 플로우를 시작하고 싶은지를 나타낸다. 인가 코드를 위한 grant type은 `code`이다. 

- scope    
클라이언트 어플리케이션이 접근하고 싶은 유저 데이터의 종류(어디까지 보고 싶은지)를 나타낸다. OAuth 프로바이터에 따라 커스텀 정의한 것을 사용할 수도 있고 OpenID Connect에 정의된 scope를 그대로 사용할 수도 있다. OpenID Connect는 나중에 자세하게 다룬다. 

- state   
클라이언트 어플리케이션의 현재 세션에 묶여진 유일한(unique), 추측하기 힘든 값이다. OAuth 서비스는 이 값과 동일한 값을 인가 코드와 함께 응답에 포함시켜야 한다. 이 파라메터는 클라이언트 어플리케이션에 있어서 CSRF 토큰과 같은 역할을 한다. 클라이언트 어플리케이션의 `/callback`엔드포인트에 요청을 한 사람(브라우저)과 OAuth 플로우를 시작한 사람이 동일한 사람이라는 것을 확인할 수 있다. 
(흐름도에서 1번과 3번이 동일한 브라우저이라는 것을 확인)

## 2. User login and consent

인가 서버가 요청을 받으면, 유저를 로그인 페이지로 리다이렉트 시킨다. 유저는 로그인이 요구되는데 이 때 사용되는 것은 소셜 미디어 계정과 같은 것이다. 

이 때 클라이언트 어플리케이션이 접근하고자 하는 데이터의 목록을 표시해준다. 이 것은 인가 요청(authorization request)에 정의된 scope에 기반한다. 유저는 이 요청에 동의하는지 또는 하지 않는지 선택할 수 있다. 

알아두어야 할 점은 한번 유저가 동의를 하면, 이 과정은 유저가 정당한 OAUth 세션을 가지고 있는 한 자동으로 완료된다는 것이다. 다시말하면, 클라이언트 어플리케이션을 나중에 다시방문하면 이 동의할지 과정을 물어보지 않는다는 것이다. 

## 3. Authorization code grant
만약 유저가 요청된 접근에 동의하면, 브라우저는 인가요청의 `redirect_uri`에 명시되었던 `/callback`엔드포인트로 유저를 리다이렉트 시킨다. GET 요청에는 인가 코드가 쿼리 파라메터로 포함된다. 설정에 따라서는 인가요청에 사용되었던 `state`파라메터가 포함되는 경우도 있다. 

```http
GET /callback?code=a1b2c3d4e5f6g7h8&state=ae13d489bd00e3c24 HTTP/1.1
Host: client-app.com
```

## 4. Access token request
클라이언트 어플리케이션이 인가 코드를 받으면, 그 것을 액세스 토큰으로 바꿀 필요가 있다. 이를 위해서 클라이언트 어플리케이션은 OAuth 서비스의 `/token` 엔드포인트에 서버 대 서버 POST 요청을 보낸다. 이 단계이후의 과정은 별도의 브라우저와 관련없는 별도 채널에서 이루어지므로 일반적으로 공격자에게 관측될 일은 없다. 

```http
POST /token HTTP/1.1
Host: oauth-authorization-server.com
…
client_id=12345&client_secret=SECRET&redirect_uri=https://client-app.com/callback&grant_type=authorization_code&code=a1b2c3d4e5f6g7h8
```

## 5. Access token grant
OAuth 서비스는 액세스 토큰발행 요청을 검증해야 한다. 모든 것이 기대된 대로 라면 서버는 클라이언트 어플리케이션에게 요청된 범위내에서 사용가능한 액세스 토큰을 발행한다.  

```
{
    "access_token": "z0y9x8w7v6u5",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "openid profile",
    …
}
```

## 6. API call
이제 클라이언트 어플리케이션은 액세스 코드를 가지고 있으므로, 리소스 서버로부터 유저 데이터를 가져올 수 있다. 이를 위해 `/userinfo` 엔드포인트에 API요청을 한다. 액세스 토큰은 `Authorization: Bearer`헤더를 통해 제출되고 이를 통해 클라이언트 어플리케이션이 데이터에 접근할 수 있음을 증명한다. 

```http
GET /userinfo HTTP/1.1
Host: oauth-resource-server.com
Authorization: Bearer z0y9x8w7v6u5
```

## 7. Resource grant
리소스 서버는 토큰이 정당한지, 그리고 그것이 현재의 클라이언트 어플리케이션의 것인지 검증해야 한다. 문제가 없으면 요청한 리소스를 응답한다. 예를 들면, 억세스 토큰의 스코프에 맞는 유저 데이터를 응답한다. 

```
{
    "username":"carlos",
    "email":"carlos@carlos-montoya.net",
    …
}
```

클라이언트 어플리케이션은 드디어 그 목적에 맞게 이 데이터를 사용한다. OAuth 인증의 경우에는, 이 데이터가 보통 ID로 사용된다. 


# Implicit grant type (암시적인 grant type)
Implicit grant type은 훨씬 간단하다. 먼저 authorization code를 얻는 대신에 유저의 동의후에 바로 액세스 토큰을 발급받는 방식이다. 

왜 모든 클라이언트 어플리케이션이 이 방식을 사용하지 않는지 의아할 수도 있는데, 왜냐하면 이 방식은 비교적 안전하지 않기 때문이다. 중요정보 교환을 하는 모든 커뮤니케이션이 브라우저 리다이렉션으로 일어난다. 이 것은 통신과정에서 액세스 토큰등이 공격에 노출될 가능성이 늘어나는 것을 의미한다. 

Implicit grant type은 `client_secret`을 쉽게 백엔드에 저장할 수 없는 싱글 페이지 어플리케이션이나 데스크톱 어플리케션에 어울린다. 

![Implicit grant type ](/images/burp-academy-oauth-grant-type-implicit.png)
(출처: https://portswigger.net/web-security/oauth/grant-types)