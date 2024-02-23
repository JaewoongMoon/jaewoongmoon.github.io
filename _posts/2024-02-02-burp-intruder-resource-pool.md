---
layout: post
title: "Burp Intruder Resource Pool설정 정리"
categories: [취약점스캐너, Burp Suite]
tags: [취약점스캐너, Burp Suite, Burp Intruder]
toc: true
last_modified_at: 2024-02-02 21:00:00 +0900
---

# 개요
Burp Intruder의 Resource pool설정에 대해 정리한다. 

# Resource Pool에서 설정 가능한 값 

![Burp Intruder의 Resource pool설정](/images/burp-intruder-new-resource-pool.png)

## Maximum concurrent requests
최대 동시에 몇 개의 요청을 날릴 것인지 등을 설정할 수 있다. 기본 값은 10이다. 

## Delay between requests
각 요청들 사이에 어느 정도 시간간격을 둘 것인지를 설정할 수 있다. 간격은 밀리세컨드 단위로 설정할 수 있다. 기본 값은 시간간격 두지 않음(연속해서 보냄)이다. 

선택지는 다음과 같다. 
- Fixed: 고정값
- With random variations: 랜덤하게 
- Increase delay in increments of: 입력한 값만큼 매번 간격의 시간이 늘어난다. 

## Automatic throttling
특정 응답 코드를 확인했을 때 요청을 줄이는 옵션이다. 기본 값은 YES이다. 

선택지 (중복 선택 가능)는 다음과 같다. 
- 429: 429응답코드는 Too Many Requests 를 의미한다. 기본값으로 설정되어 있다.
- 503: 503은 Service Unavailable을 의미한다. 요청이 너무 많을 때 나타나기도 한다. 옵션으로 선택가능하다. 
- Other: 다른 응답 코드를 추가할 수있다. CSV포맷으로 콤마를 붙여서 여러개 지정할 수 있다. ex) 504,505
