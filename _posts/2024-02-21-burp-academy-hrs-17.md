---
layout: post
title: "Burp Academy-HTTP Request Smuggling 관련 취약점: Bypassing access controls via HTTP/2 request tunnelling"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, HTTP Request Smuggling]
toc: true
last_modified_at: 2024-02-21 21:00:00 +0900
---

# 개요
- HTTP Request Smuggling 취약점 문제이다. 여기서부터는 HTTP 프로토콜2를 사용하는 서버에 대한 스머글링을 사용한다.Advanced 토픽이다. 
- 문제 주소: https://portswigger.net/web-security/request-smuggling/advanced/request-tunnelling/lab-request-smuggling-h2-bypass-access-controls-via-request-tunnelling
- 취약점 설명페이지: https://portswigger.net/web-security/request-smuggling/advanced/request-tunnelling
- 난이도: EXPERT (어려움)

# Request Tunnelling 개요
- 지금까지의 스머글링은 프론트엔드 서버와 백엔드 서버가 커넥션을 공유하기 때문에 다른 유저에게 영향을 미치는 경우였다. 
- 어떤 시스템은 커넥션을 동일한 IP로부터 오는 경우에만 재사용하기도 한다. 이 경우, 이 커넥션은 해당 IP전용이 되므로 이 유저가 보낸 요청에 대해서만 응답이 보내진다. 일종의 전용터널처럼 된다. 다른 유저가 사용하는 터널에서 이 터널로는 간섭할 수 없는 것이다.
- 지금까지의 스머글링은 통하지 않지만, 이런 경우에도 보안 메커니즘을 우회하거나, 웹 캐시를 오염시키는 방식으로 공격이 가능한 경우가 있다. 

## Request tunnelling with HTTP/2
- 리퀘스트 터널링은 스머글링 요청에 대해서 응답이 두개 돌아오는지를 보고 판단가능하다. 
- 리퀘스트 터널링은 HTTP/1과 HTTP/2 양쪽 모두 가능하다. 하지만 HTTP/1쪽이 탐지가 어렵다. 
- 왜냐하면 HTTP/1에서는 기본적으로 지속되는 커넥션 속성 `keep-alive` 가 동작하기 때문에, 두개의 응답을 받았다고 해도 성공적으로 스머글링이 된 것인지 판단하기 어렵다. 
- 한편, HTTP/2에서는 각각의 스트림이 오직 하나의 요청과 응답을 포함하므로, HTTP/2 요청의 응답에 HTTP/1 응답이 섞여 있다면 성공적으로 스머글링을 수행(터널링)했다는 판단할 수 있다. 

