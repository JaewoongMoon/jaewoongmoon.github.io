---
layout: post
title: "Burp Academy-HTTP Request Smuggling 관련 취약점: HTTP request smuggling, basic CL.TE vulnerability"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, HTTP Request Smuggling]
toc: true
last_modified_at: 2023-12-27 09:50:00 +0900
---

# 개요
- HTTP Request Smuggling 취약점 문제이다. 
- 이는 2019년 8월에 발표된 James Kettle의 [HTTP Desync Attacks: Request Smuggling Reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)에 기초한 내용이다. 
- HTTP Request Smuggling 취약점 문제 1번부터 12번까지는 이 연구에 기초한 내용이다. HTTP/1.1에서 프론트엔드 서버와 백엔드 서버가 CL헤더와 TE헤더를 사용하는 패턴이다.
- 문제 주소: https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te
- 취약점 설명페이지: https://portswigger.net/web-security/request-smuggling
- 난이도: PRACTITIONER (보통)

# 랩 개요
- 이 랩은 프론트 엔드 서버와 백엔드 서버로 구성되어 있고, 프론트 엔드 서버는 chunked encoding 을 지원하지 않는다. 
- 프론트 엔드 서버는 GET이나 POST가 아닌 요청은 거부한다. 
- 랩을 풀려면 백엔드 서버에게 HTTP요청을 밀반입해서, 백엔드 서버가 다음 요청을 처리할 때 GPOST 라는 메서드를 처리하도록 만들면 랩이 풀린다. 
- 팁: 수동으로 HTTP Request Smuggling을 수행하는 것은 힘들다. `HTTP Request Smuggler` Burp 확장 프로그램을 이용하면 쉽게 할 수 있다. 

```
This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding. The front-end server rejects requests that aren't using the GET or POST method.

To solve the lab, smuggle a request to the back-end server, so that the next request processed by the back-end server appears to use the method GPOST.

Tip
Manually fixing the length fields in request smuggling attacks can be tricky. Our HTTP Request Smuggler Burp extension was designed to help. You can install it via the BApp Store.
```

# 도전
1. 일단 팁에서 알려준 대로  `HTTP Request Smuggler`를 한번 사용해보자. BApp스토어에서 설치후 `GET /` 요청을 선택 후 마우스 오른쪽 클릭 Extensions > HTTP Request Smuggler > Smuggle probe 를 선택한다. 선택하면 테크닉들을 선택하는 팝업이 뜨는데 일단 디폴트상태로 실행했다.

![HTTP Request Smuggler 사용](/images/burp-academy-hrs-1-1.png)

2. 스캔 상태는 Extensions > Installed > output 에서 볼 수 있다. 다음과 같은 메세지가 출력된다. 

```
Using albinowaxUtils v1.2
This extension should be run on the latest version of Burp Suite. Using an older version of Burp may cause impaired functionality.
Loaded HTTP Request Smuggler v2.16
Updating active thread pool size to 8
Loop 0
Loop 1
Queued 1 attacks from 1 requests in 0 seconds
Unexpected report with response
Completed request with key https0a4000d8032d890b84102d8a003b005b.web-security-academy.netGET200HTML: 1 of 1 in 172 seconds with 48 requests

```

3. Pro 버전을 사용중이라면 스캔 결과가 Dashboard에 나타난다. 몇 가지 패턴의 스머글링이 가능한 것으로 나온다. 

![HTTP Request Smuggler 스캔 결과 ](/images/burp-academy-hrs-1-2.png)

4. 그중 하나인 CL.TE 패턴을 확인해본다. 확신도는 의외로 Tentative (자신없는)다. 

![CL.TE 지적 확인](/images/burp-academy-hrs-1-3.png)

5. 직접 수동으로도 체크해보기로 한다. GET 요청을 Repeater로 보낸다. 프로토콜은 HTTP 1.1로 변경한다. 그리고 Repeater 세팅에서 `Update Content-Length`의 체크를 해제한다. Content-Length를 일부러 틀리게 보내야 하는데 이 기능이 체크되어 있으면 항상 정확한 Content-Length 값이 보내지기 때문이다.

![Repeater Update Content-Length 설정](/images/burp-academy-hrs-1-4.png)

6. 전형적인 CL.TE 체크 페이로드를 준비한다. 다음과 같이 생겼다. 

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 4

1\r\n
Z\r\n
Q
```

프론트 엔드는 CL헤더를 보고, 백엔드는 TE헤더를 보는 경우, 위의 페이로드를 보내면 타임아웃이 발생한다. 이유는 다음과 같다. 

- 프론트엔드는 CL헤더를 보기 때문에 4바이트인 `1\r\nZ`까지를 POST의 바디로 인식하여 여기까지를 백엔드 서버로 보낸다. 
- 백엔드 서버는 TE헤더를 보기 때문에 `0\r\n\r\n`가 올때까지 대기한다. (TE헤더는 `0\r\n\r\n`을 HTTP요청의 끝으로 인식한다.) 
- 백엔드가 계속 대기하기 때문에 타임아웃이 발생한다.

**CL.TE패턴에서는 페이로드에 `0\r\n\r\n`이 없다는 것이 타임아웃을 발생시키는 요인이다.**

7. 실제로 보내본다. 타임아웃이 발생하는 것을 볼 수 있다. CL.TE 타입의 스머글링이 가능해보인다. 

![타임아웃 발생](/images/burp-academy-hrs-1-5.png)

8. 이제 백엔드가 'GPOST' 요청을 처리하도록 해본다. POST는 HTTP 요청의 메소드 이름이다. 따라서 G라는 의미가 없는 문자열을 밀입하면 좋을 것 같다. "HTTP 요청 + G + 다음 HTTP 요청" 과 같은 이미지다. (TE 헤더에 따르는) 백엔드를 대기시키면 타임 아웃이 발생해 버리므로 탐지용 페이로드와는 다른 위치에 0\r\n\r\n을 넣을 필요가 있다. 다음과 같다. 

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 6

0\r\n
\r\n
G
```

위 요청을 보내면 어떻게 될까? CL헤더 값이 6이므로 프론트엔드는 G까지를 포함해서 백엔드에 전송할 것이다. 백엔드는 TE헤더를 보므로 G의 바로 직전까지를 하나의 요청으로 인식해서 처리할 것이다. 백엔드에는 G가 있는 상태이다. 이 상태에서 다시 한번 동일한 요청을 보낸다. 그러면 프론트엔드는 이 요청을 백엔드에 전달하고 백엔드에서는 이미 받았던 G에, 새롭게 받은 POST ~ 부분을 합쳐서 처리한다. 즉, 백엔드 서버가 인식해서 처리하는 HTTP 요청은 다음과 같은 모양이다. 

```http
GPOST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 6

0\r\n
\r\n
```

따라서 이 요청에 대한 응답으로 `GPOST` 라는 메서드는 알아먹을 수 없다는 메세지가 출력된다. 

![GPOST 처리 결과](/images/burp-academy-hrs-1-6.png)

9. 잠시 후에 풀이에 성공했다는 메세지가 나타난다.

![GPOST 처리 결과](/images/burp-academy-hrs-1-success.png)

# 감상
- 가장 기본적인 HRS 패턴인 CL.TE를 이해하기에 좋은 문제다. 
- 프론트엔드에게는 하나의 HTTP 요청처럼 보이게 하고, 백엔드에서는 두 개의 HTTP 요청으로 처리되도록 하는 것이 기본적인 접근법이라는 것을 배웠습니다.