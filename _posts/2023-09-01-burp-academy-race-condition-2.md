---
layout: post
title: "Burp Academy-레이스컨디션 관련 취약점: Limit overrun race conditions"
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
요청을 병렬로 보내기 위한 다음과 같은 기본형이 소개되어 있따. 

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


# 참고 
- https://github.com/PortSwigger/turbo-intruder/blob/master/resources/examples/race-single-packet-attack.py
- https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack