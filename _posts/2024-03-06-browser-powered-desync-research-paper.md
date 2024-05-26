---
layout: post
title: "Browser-Powered Desync Attacks: A New Frontier in HTTP Request Smuggling 메모"
categories: [보안취약점, Burp Research]
tags: [보안취약점, Burp Research, HTTP Request Smuggling]
toc: true
last_modified_at: 2024-03-04 21:00:00 +0900
---

# 개요
- 2022년 8월에 발표된 James Kettle의 [Browser-Powered Desync Attacks: A New Frontier in HTTP Request Smuggling](https://portswigger.net/research/browser-powered-desync-attacks)를 읽고 메모한 페이지이다. 
- 이 문서는 HTTP handling anomalies, Client-side desync, Pause-based desync, Conclusion 총 네 개의 챕터로 이루어져 있다. 

# HTTP handling anomalies
이 챕터에서는 뒤에 따르는 발견으로 이어지는 네가지 현상을 소개하고 있다. 

## Connection state attacks
가장 많이 보는 잘못된 Web 서버 구현은 동일한 TLS 커넥션내에서 보내는 HTTP/1.1 요청이 모두 동일한 Host헤더를 가지고 있을 것이라고 상정한다는 것이다. 웹 브라우저가 이 상정에서 동작하기 때문에 일반적인 경우는 문제가 없지만 누군가가 Burp를 키면 상황이 달라진다. 

### First-request validation
- 리버스 프록시 서버는 종종 Host헤더를 보고 어떤 백엔드 서버로 해당 요청을 전송할지를 결정한다. 등록된 화이트리스트에 따라 백엔드서버에 전송할지를 결정한다.  
- 그런데 어떤 리버스 프록시 서버는 TLS 커넥션의 첫번째 요청만을 체크하는 경우가 있다. 이 경우 동일한 커넥션에서 두번째 요청부터는 접근금지된 곳에 접근할 수 있게 된다.  
- 다행히도 흔한 경우는 아니다. 

### First-request routing
- 첫번째 요청의 Host헤더를 보고 어느 백엔드로 보낼지 결정한 후, 이후의 요청은 모두 동일한 백엔드로 보내는 거동을하는 경우다.
- 이 것자체는 취약점이 아니지만 공격자가 원하는 백엔드에 접근할 수 있다는 점에서 Host헤더를 공격하는 테크닉(패스워드 리셋 포이즈닝, 웹 캐시 포이즈닝)과 결합되면 취약점이 발생할 수도 있다. 
- First-request validation, First-request routing은 HTTP Request Smuggler의 'connection-state probe'옵션으로 체크할 수 있다. 

## The surprise factor
- AWS의 ALB는 HTTP 요청을 1.1로 다운그레이드해서 백엔드로 보내줄 때 TE헤더를 붙여주는 거동이 있었다. 이를 통해 공격자는 바디에 `0\r\n\r\n`을 붙이는 방법으로 스머글링을 할 수 있었다. 

## Detecting connection-locked CL.TE

## CL.0 browser-compatible desync

## H2.0 on amazon.com


# Client-side desync
전통적인 desync 공격은 프론트 엔드 서버와 백엔드 서버 사이에서 이루어 진다. 따라서 프론트 엔드와 백엔드 서버를 동시에 사용하지 않는 경우에는  불가능했다. 이 것을 이제부터 서버사이드 디싱크(desync)라고 부르겠다. 

대부분의 서버 사이드 디싱크는 Burp Suite와 같이 특별한 HTTP 요청을 보낼 수 있는 클라이언트 툴이 필요하다. 하지만 이전 장의 amazon의 예에서 봤듯이, 서버사이드 디싱크는 웹 브라우저를 통해서 가능한 경우도 있다. 

또한 웹 브라우저와 프론트엔드 서버 사이에 일어날 수 있는 디싱크를 Client-Side Desync (CSD)라고 부르겠다. 이는 하나의 서버로만 이루어진 웹 사이트에서 가능할 수 있다. 

CSD공격은 victim을 공격자의 웹 사이트에 접속시킨다. 이 웹 사이트는 취약한 웹 사이트로 두개의 크로스 도메인 요청을 발생시킨다. 여기에서 두번째 요청이 해로운 응답을 유발시킨다. 이 것은 보통 공격자에게 victim 계정의 제어권을 주는 것이다. 

![](/images/browser-powered-desync-1.png)
*출처: https://portswigger.net/research/browser-powered-desync-attacks#cl.0*

## 방법론 (Methodology)
CSD를 찾고 exploit하는데는 서버 사이드 디싱크의 컨셉을 많이 재사용할 수 있다. 가장 큰 차이점은 모든 exploit 이 victim의 브라우저에 의해서 수행된다는 점이다. 이 것은 해킹툴을 사용하는 것보다 더욱 복잡하고 공격자가 컨트롤하기 어려운 환경이다. 따라서 조사하기 어렵다. 수 많은 시간을 들여서 조사하면서 얻은 방법론을 공유하겠다. 

![](/images/browser-powered-desync-2.png)
*출처: https://portswigger.net/research/browser-powered-desync-attacks#cl.0*

### 찾기(detect)


### 확신하기(Confirm)


### 탐험하기(Explore)


#### 저장하기(Store)



#### 체인&피벗(Chain&Pivot)



### 공격하기(Attack)




## 케이스 스터디(Case studies)

### Akamai - stacked HEAD

### Cisco Web VPN - client-side cache poisoning

### Verisign - fragmented chunk

### Pulse Secure VPN





# Pause-based desync

# Conclusion 