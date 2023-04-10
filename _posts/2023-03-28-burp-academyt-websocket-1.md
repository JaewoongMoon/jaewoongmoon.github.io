---
layout: post
title: "Burp Academy-WebSocket 첫번째 문제: Manipulating WebSocket messages to exploit vulnerabilities"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, WebSocket취약점]
toc: true
---

# 개요
- Manipulating WebSocket messages to exploit vulnerabilities
- WebSocket 취약점 설명 주소: https://portswigger.net/web-security/websockets
- 문제 주소: https://portswigger.net/web-security/websockets/lab-manipulating-messages-to-exploit-vulnerabilities
- 난이도: APPRENTICE (쉬움)

# 문제 설명
문제 서버의 온라인 숍에는 웹소켓으로 구현된 라이브챗 기능이 있다.   
웹 소켓 메세지를 통해 alert()팝업이 뜨도록 만들면 된다. 

```
This online shop has a live chat feature implemented using WebSockets.

Chat messages that you submit are viewed by a support agent in real time.

To solve the lab, use a WebSocket message to trigger an alert() popup in the support agent's browser.
```

# 풀이 
온라인 숍에 들어가면 우측 상단에 라이브챗링크가 보인다. 여기를 클릭해서 들어가면 채팅을 할 수 있다.    
웹 소켓 메세지는 Proxy 메뉴의 WebSockets history탭에서 확인할 수 있다. 일단 대충 쳐봤을 때 다음과 같은 메세지가 전송되는 것을 확인했다. 

![WebSockets history탭](/images/burp-academy-websocket-1-1.png)

-> To server   

```json
{"message":"this is test"}
```

<- To client   

```json
{"user":"You","content":"this is test"}
```

## 1차 시도 
- 채팅창에 `<script>alert(1);</script>`를 보내봤다. 팝업은 뜨지 않았다. 
- 프록시에 기록된 메세지를 확인해보니 다음과 같이 HTML에스케이프된 상태로 서버로 전송되고 있었다. 

-> To server   

```json
{"message":"&lt;script&gt;alert(1);&lt;/script&gt;"}
```

## 2차 시도
- 채팅창에 메세지를 적고 Send를 눌렀을 때의 메세지를 Burp Proxy로 intercept한 뒤에 `<script>alert(1);</script>`로 변경해서 보내봤다. 

-> To server   

```json
{"message":"<script>alert(1);</script>"}
```

응답은 다음과 같았다. 닫는 태그의 `/` 앞에 역슬래시가 붙어있다. 이러면 특수문자 이스케이프가 되므로 닫는 태그로 인식하지 않아서인지 script가 동작하지 않았다. 

<- To client   

```json
{"user":"You","content":"\t<script>alert(1);<\/script>"}
```

## 3차 시도 

서버로 보내는 메세지를 Repeater로 보내서 테스트해본다. Reconnect 버튼을 눌러서 재접속할 필요가 있다. 

![Repeater Websocket Reconnect](/images/burp-academy-websocket-reconnect.png)

2차시도에서 닫는 태그를 쓸 수 없는 것을 알았으므로 닫는 태그가 필요없는 XSS 페이로드를 보내본다. 예를들면 `<img src=1 onerror='alert(1)'>`다. 

![XSS 페이로드](/images/burp-academy-websocket-1-3.png)

결과는 다음과 같다. 

이미지 태그가 삽입되었다. 

![이미지 태그](/images/burp-academy-websocket-1-2.png)

그리고 alert팝업이 뜨고, 문제풀이에 성공했다는 팝업이 뜬다. 

![문제 풀이완료](/images/burp-academy-websocket-1-success.png)