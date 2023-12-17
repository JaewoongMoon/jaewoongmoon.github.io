---
layout: post
title: "Burp Academy-Host 헤더 관련 취약점: SSRF via flawed request parsing"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Host헤더]
toc: true
last_modified_at: 2023-12-15 09:50:00 +0900
---

# 개요
- HTTP Host 헤더 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/host-header/exploiting/lab-host-header-host-validation-bypass-via-connection-state-attack
- 취약점 설명페이지 1: https://portswigger.net/web-security/host-header
- 취약점 설명페이지 2: https://portswigger.net/web-security/host-header/exploiting#connection-state-attacks
- 난이도: PRACTITIONER (보통)

# 취약점 개요 (Connection state attacks)
- 퍼포먼스 이유때문에 많은 웹 사이트가 동일한 클라이언트로부터의 여러개의 요청/응답을 처리하기 위해 커넥션을 재사용한다. 
- 그러나 HTTP서버가 잘못 구현되면, 예를 들어, 새로운 커넥션의 첫번째 요청의 Host헤더만 검증한다면, 보안상 취약점이 발생할 수 있다. 

# 랩 개요
- 이 랩은 호스트헤더 인젝션을 통해 routing-based SSRF가 가능하다 .
- 프론트 엔드 서버는 Host헤더를 검증하지만 커넥션의 첫번째 요청만 검사한다. 
- 이 것을 이용해 인터널 IP 주소 192.168.0.1 에 존재하는 관리자 패널에 접근해서 carlos유저를 삭제하면 문제가 풀린다. 
- 힌트: 이 랩을 풀려면 Burp Suite 2022.8.1 이후 버전이 필요하다. 이 버전에서 Repeater에서 요청을 동일한 혹은 별도의 커넥션으로 연속으로 보내는 기능을 제공했다. 이 것을 이용해야 하는 것 같다.
- 즉, 첫번째 요청은 Host헤더에 문제가 없는 도메인을 지정하고, 두번째 요청에는 Host헤더의 값을 192.168.0.1/admin 으로 지정하는 것이다.

```
This lab is vulnerable to routing-based SSRF via the Host header. Although the front-end server may initially appear to perform robust validation of the Host header, it makes assumptions about all requests on a connection based on the first request it receives.

To solve the lab, exploit this behavior to access an internal admin panel located at 192.168.0.1/admin, then delete the user carlos.

Hint: Solving this lab requires features first released in Burp Suite 2022.8.1.
```

# 풀이 