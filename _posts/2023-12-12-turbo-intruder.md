---
layout: post
title: "Burp Suite - Turbo Intruder정리"
categories: [Burp Suite]
tags: [Burp Suite, Turbo Intruder]
toc: true
last_modified_at: 2023-12-28 09:50:00 +0900
---

# 개요
- Burp Suite의 확장 프로그램인 Turbo Intruder에 대해 정리해둔다. 
- BApp Store에서 간단히 설치가 가능하다.
- Turbo Intruder는 하나의 호스트에 대해 대량의 HTTP 요청을 보내서 테스트하고 싶을 때 사용하면 좋다. 
- 대량의 HTTP요청을 보내서 테스트하고 싶을 때란 주로 `HTTP Request Smuggling`이나 `Race Condition`, 워드 리스트에 있는 값을 하나씩 모두 시도와 같은 것을 테스트하고 싶을 때다. 
- 개발언어는 메인으로 코틀린을, 서브로 파이썬을 사용한 것으로 보인다. 

# 사용방법
- 파이썬 스크립트를 작성해서 Burp Suite에 등록하여 실행하는 방식이다. 
- Burp Proxy나 Burp Repeater의 HTTP 요청에서 마우스 오른쪽 버튼을 눌러서 Extensions > Turbo Intruder > Send to turbo intruder를 선택하면 된다. 이 때 동적으로 변경시키고 싶은 파라메터부분이 있다면 선택해두면(Highlight), Turbo Intruder화면에서 `%s` 로 바껴있는 것을 볼 수 있다. 여기에 파라메터 리스트의 값이 하나씩 들어가게 된다. 
- 물론 Turbo Intruder화면에서 수동으로 파라메터를 입력하고 싶은 부분을 `%s`로 지정해도 된다. 
- 기본형은 다음과 같이 생겼다. 

![Turbo Intruder Basic](/images/burp-turbo-intruder-basic.png)

```py

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False
                           )

    # queue에 HTTP요청을 넣는다. 이 경우에는 `/usr/share/dict/words`에 있는 워드개수만큼의 HTTP 요청이 큐에 등록된다. 
    for word in open('/usr/share/dict/words'):
        # queue의 첫번째 파라메터는 HTTP요청이, 두번째 파라메터는 %s 부분이 치환될 값이 들어간다. 
        # 두번째 파라메터를 생략하면 단순히 동일한 HTTP 요청이 큐에 삽입된다. 
        engine.queue(target.req, word.rstrip()) 

 
# 결과 윈도우에 출력할지 말지 조건을 작성한다. 
def handleResponse(req, interesting):
    # currently available attributes are req.status, req.wordcount, req.length and req.response
    if req.status != 404:
        table.add(req)
```

# HTTP 요청 엔진 튜닝하기 - RequestEngine 파라메터 
RequestEngine에서 사용가능한 파라메터를 목적에 맞게 지정하는 것으로 성능을 최적화(튜닝)할 수 있다. 

다음 파라메터가 존재한다. 
- endpoint: 테스트하려고 하는 대상을 지정한다. 보통 target.endpoint에서 바뀔 일은 없을 것이다. 
- concurrentConnections: 동시에 수립할 커넥션 개수이다. 병렬로 처리되므로 커넥션 개수가 많을수록 빨라진다. 그러나 대상 서버에도 리소스에 한계가 있으니 적절한 선에서 선택하는게 좋다. 보통 30~50이 많이 쓰이는 것 같다. 기본값은 **50**이다. 
- requestsPerConnection: 커넥션당 보낼 HTTP요청 개수이다. 기본값은 **100**이다.
- resumeSSL: 정확히 모르겠다. [여기](https://blog.cloudflare.com/tls-session-resumption-full-speed-and-secure)를 보면 한번 수립한 SSL 세션을 재사용하는 개념인 것 같다. 기본값은 **True**이다. 속도 우선이라면 True로, 정확도 우선이라면 False로 지정하면 될 것 같다. 
- timeout: 응답이 없을 경우 몇 초 기다린 후에 타임아웃시킬 것인지. 기본값은 **10**이다.
- maxQueueSize: 엔진의 큐 사이즈. 기본값은 **100**이다. 아마 이 것을 튜닝할 일은 없을 것 같다. 
- pipeline: HTTP 파이프라인 기능을 사용할 것인가. HTTP 파이프라인은 HTTP/1.1의 기능으로, 하나의 TCP 커넥션안에서 서버의 응답을 기다리지 않고 바로 다음 요청을 보낼 수 있는 기능이라고 한다. 서버와 클라이언트 모두 파이프라인을 지원해야 사용할 수 있다. 참고로 HTTP/2에서는 `multiplexing`으로 대체 되었다. 기본 값은 **False**이다.
- maxRetriesPerRequest: 요청당 몇 번까지 재시도할 것인가. 기본 값은 **3**이다.
- engine: 엔진의 동작 방식을 지정가능하다. 보통 `Engine.THREADED`가 많이 쓰인다. 속도는 대상 서버가 지원한다면 `Engine.HTTP2`가 가장 빠르고, 다음은 `Engine.THREADED`, `Engine.BURP2`, `Engine.BURP` 순이다.

```py
engine = RequestEngine(endpoint=target.endpoint,
                        concurrentConnections=40,
                        requestsPerConnection=1,
                        resumeSSL=False,
                        timeout=1,
                        pipeline=True,
                        maxRetriesPerRequest=0,
                        engine=Engine.THREADED,
                        )
```


# 화면에 표시할 흥미로운 응답 판별하기 (handleResponse 패턴)
- handleResponse에 조건을 추가해서 어떤 응답을 화면에 표시할지를 결정한다. 
- 화면에 표시하는 기능은 부하가 많이 걸리는 작업이다.(Java Swing을 쓴다.) 따라서 적절한 응답만 table에 추가하는게 리소스 최적화와도 연결되는 길이다.

## 응답에 특정 문자열이 포함되어 있는지로 분기

```py
if 'Set-Cookie: xxxx' in req.response:
    table.add(req)
```

## 응답 코드로 분기

```py
if req.status != 302:
    table.add(req)
```

또는 다음과 같이 `@`를 써서 스테이터스 코드를 지정가능하다. 

```py
@MatchStatus(404)
def handleResponse(req, interesting):
    table.add(req)
```

# Race Condition 용 스크립트
샘플에 있는 `race.py`코드이다. 레이스 컨디션을 체크할 때는 queue에 세번째 파라메터로 `gate`를 지정해준다. 동일한 이름태그(`gate`)가 붙은 HTTP요청이 준비될 때까지 기다려준다는 것 같다. 레이스 컨디션이므로 동시에 HTTP요청을 보낼 필요가 있다. 모든 HTTP요청이 전송준비될 때까지 기다렸다가 한번에 보내는 방식인 것 같다. 

```py
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=100,
                           pipeline=False
                           )

    # the 'gate' argument blocks the final byte of each request until openGate is invoked
    for i in range(30):
        engine.queue(target.req, target.baseInput, gate='race1')

    # wait until every 'race1' tagged request is ready
    # then send the final byte of each request
    # (this method is non-blocking, just like queue)
    engine.openGate('race1')

    engine.complete(timeout=60)


def handleResponse(req, interesting):
    table.add(req)
```


# 알게된 것 / 팁 
- 터보 인트루더는 아마 파이썬 2.x 버전으로 쓰여진 것으로 보인다. 
- Python3에서 자주 쓰이는 f-string을 사용할 수 없다. (사용하려고 하면 SyntaxError "no viable alternative at input ...) 에러가 발생한다. 
- Content-Length 헤더의 값은 자동으로 업데이트 해준다. (요청에 하드코딩해서 적더라도 맞는 값으로 업데이트된다.)

## 궁금점
- CL 업데이트를 원하지 않는 경우에는 어떻게 해야하지?


# 참고 URL
- Turbo Intruder 소개 https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack
- Turbo Intruder 샘플: https://github.com/PortSwigger/turbo-intruder/tree/master/resources/examples
- SSL Resume기능에 대해: https://blog.cloudflare.com/tls-session-resumption-full-speed-and-secure
- HTTP Pipelining: https://en.wikipedia.org/wiki/HTTP_pipelining