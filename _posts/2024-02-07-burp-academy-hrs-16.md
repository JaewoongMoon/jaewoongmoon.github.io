---
layout: post
title: "Burp Academy-HTTP Request Smuggling 관련 취약점: HTTP/2 request splitting via CRLF injection"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, HTTP Request Smuggling]
toc: true
last_modified_at: 2024-02-20 21:00:00 +0900
---

# 개요
- HTTP Request Smuggling 취약점 문제이다. 여기서부터는 HTTP 프로토콜2를 사용하는 서버에 대한 스머글링을 사용한다.Advanced 토픽이다. 
- 문제 주소: https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-request-splitting-via-crlf-injection
- 취약점 설명페이지: https://portswigger.net/web-security/request-smuggling/advanced#http-2-request-splitting
- 난이도: PRACTITIONER (보통)

# 취약점 개요 (HTTP/2 request splitting)
- HTTP/2에서는 개행문자(`\r\n`)가 특별한 의미를 가지지 않기 때문에 헤더 값에 연속되는 개행문자(`\r\n\r\n`)를 지정하는 것으로 이후를 새로운 요청으로 인식시킬 수 있다. 
- 백엔드에서 프로토콜이 HTTP/1.1로 다운그레이드되는 경우에 공격 가능하다. 

# 랩 개요
- 이 랩은 프론트 엔드 서버와 백엔드 서버로 구성되어 있다. 프론트 엔드 서버는 HTTP/2 요청을 백엔드에 전송할 때 HTTP1으로 다운그레이드한다. 그리고 인커밍 헤더를 적절히 새니타이즈하지 못한다. 이로 인해서 스머글링이 가능하다. 
- 랩을 풀려면 응답 큐 포이즈닝(response queue poisoning)을 이용해서 admin패널에 접근하여 carlos유저를 삭제하면 된다. 
- admin은 10초마다 웹 사이트를 방문한다. 

```
This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests and fails to adequately sanitize incoming headers.

To solve the lab, delete the user carlos by using response queue poisoning to break into the admin panel at /admin. An admin user will log in approximately every 10 seconds.

The connection to the back-end is reset every 10 requests, so don't worry if you get it into a bad state - just send a few normal requests to get a fresh connection.
```

# 풀이 시도
여기서부터는 HTTP 요청 분리(Splitting)문제다. CRLF Injection을 응용해서 HTTP 요청을 분리시키는 것으로 백엔드 서버에 요청을 스머글링한다. 그러면 결과적으로 응답 큐 포이즈닝이 발생해서 (운이 좋으면) 관리자 유저에게 갈 응답을 얻어낼 수 있다. 이를 통해 관리자 유저로 접근, carlos 유저를 삭제하면 된다. 

1. 일단 먼저 TE 패턴의 스머글링 요청을 보내본다. HTTP/2요청 헤더에 `Foo: bar\r\nTransfer-Encoding: chunked` 를 추가하고 보디 부분은 다음과 같이 설정한다. 

```http
0

SMUGGLED
```

2. 요청을 몇 번 보내보면 항상 200응답이 회신된다. 이 패턴으로는 스머글링이 안되는 것 같다. 

3. 헤더를 `Foo: bar\r\n\r\n`으로 지정한다. 보디는 GET /404 HTTP/1.1 로 지정해서 보내본다. 몇 번 보내면 다음과 같이 400 Bad Request응답이 회신된다. 스머글링한 요청자체는 제대로 된 HTTP 요청으로 처리되지 않았지만 CRLF 인젝션자체는 통하는 것 같다. 

![CRLF 인젝션 시도](/images/burp-academy-hrs-16-1.png)

4. 스머글링용 요청을 다음과 같이 이것 저것 헤더를 추가해봐도 마찬가지로 400응답이 돌아온다. HTTP/2헤더의 `Foo: bar` 헤더에 지정한 `\r\n`의 개수를 한개에서 세개까지 조정해가며 테스트해봐도 마찬가지다. 

```http
GET / HTTP/1.1
Host: 0abe000304827a5e819f215a00ac003c.web-security-academy.net
Cookie: session=G8pUSmjVnlzcmiu0rrx2vbc3of5vzCEf
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36
Foo: bar

```

5. 조금 생각을 바꿔본다. 스머글링 요청을 아예 헤더에 삽입할 수도 있지 않을까? 다음과 같이 foo헤더에 스머글링 요청을 지정하고 요청을 보내자 404응답이 돌아왔다! 스머글링에 성공한 것이다. 

![CRLF 인젝션 시도2](/images/burp-academy-hrs-16-2.png)

6. 이제 관리자 유저의 응답을 낚아채면 된다. 원본 요청(HTTP/2 요청)도 /404를 지정한다. 이렇게 하면 거의 항상 404응답이 돌아올 것이다. 응답 큐 포이즈닝 덕분에 운 좋게 관리자의 응답을 받았을 경우에는 302라던가 다른 응답 코드일 것이다. 

7. 그런데 수동으로 수십번 요청을 보내봤지만 항상 404응답이었다. Intruder는 HTTP/2 요청 헤더를 바꾼 부분(Kettled Request)를 보낼 수 없으므로 사용할 수 없다. 

8. Turbo Intruder를 검토해보자. Turbo Intruder로 Kettled Request를 보낼 수 있는지를 테스트하기 위해 다음과 같이 설정한 후에 보내봤다. 

```py
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=10,
                           requestsPerConnection=10,
                           pipeline=False
                           )

    for i in range(0, 1000):
        engine.queue(target.req)

def handleResponse(req, interesting):
    if req.status == 404:
        table.add(req)
```

9. 테스트 결과 404응답이 돌아오지 않았다.  Turbo Intruder로는 Kettled Request를 보낼 수 없어 보인다. 

10. 따라서 Repeater로 참을성있게 Kettled Request를 계속 보내는 방법 밖에 없어 보인다. 

11. 음... 그러나 몇 번 시도해봐도 역시 404이외의 응답은 얻을 수 없었다. 어쩔 수 없다. 답을 보자. 

12. 답을 봤으나 별다른 건 없었다. 대부분 404응답이 오지만 302를 얻을 때까지 반복한다! 라는게 답이었다... 😂

13. 다시 새로운 랩에서 시도해본다. 운이 좋게도 10번정도 시도 후에 302응답을 얻어냈다! 

![302응답 확인](/images/burp-academy-hrs-16-3.png)

14. 위에서 얻은 관리자 세션토큰으로 랩에 억세스하면 관리자 메뉴가 보인다. Carlos 유저를 삭제한다. 

![관리자 메뉴 확인](/images/burp-academy-hrs-16-4.png)

15. 삭제에 성공하면 랩이 풀렸다는 메세지가 표시된다! 

![풀이 성공](/images/burp-academy-hrs-16-success.png)