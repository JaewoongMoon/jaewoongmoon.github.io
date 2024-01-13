---
layout: post
title: "Burp Academy-Host 헤더 관련 취약점: Host validation bypass via connection state attack"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Host헤더]
toc: true
last_modified_at: 2023-12-18 09:50:00 +0900
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
1. `/admin` 으로 요청을 보내본다. 그러면 `404 Not Found`가 회신되는 것을 알 수 있다. 
![/admin요청 확인](/images/burp-academy-host-header-6-2.png)

2. Host헤더의 값을 `192.168.0.1`로 바꿔서 보내본다. 그러면 이번에는 문제 랩 서버로 301 리다이렉트 응답이 돌아오는 것을 볼 수 있다. 단순한 Host 헤더 인젝션으로는 접근이 안된다. 

![내부IP로 접근 확인](/images/burp-academy-host-header-6-1.png)

3. 동일한 커넥션 내에서 두 개의 요청을 연속해서 보내본다. 뒤의 요청은 Host헤더의 값이 192.168.56.1로 되어 있다. Repeater에서 +버튼을 클릭하고 Create tab group을 선택한다. 

![Create tab group](/images/burp-academy-host-header-6-3.png)

4. 두 개의 요청을 선택해서 탭 그룹으로 만든다. Send group in sequence (single connection)을 선택한다. 

![요청을 동일 커넥션에서 연속해서 보내기](/images/burp-academy-host-header-6-4.png)

※ 참고로 이 때 프로토콜 버전은 1.1이다. 프로토콜 버전을 2로 선택하면 다음과 같은 에러 메세지가 Repeater의 하단에 출력된다. `Server APLN does not advertise HTTP/2 support. you can force http/2 from the Repeater menu.`

APLN은 Application-Layer Protocol Negotiation의 약자다. 서버측에서 자신으 HTTP/2를 지원하지 않는다고 응답했기 떄문에 나타나는 에러다. 

![HTTP/2 에러](/images/burp-academy-host-header-6-5.png)

이 때 Burp Repeater의 설정메뉴에서 Allow HTTP/2 APLN override를 선택하면 서버측의 응답을 무시하고 HTTP/2로 요청을 보낼 수 있다. 숨겨진 HTTP/2 엔드포인트에 대해 쓸 수 있는 방법이다. 하지만 이번 문제에서는 이렇게 해도 서버측에서 응답은 없었다. 

![ Allow HTTP/2 APLN override](/images/burp-academy-host-header-6-6.png)

5. Send버튼을 누르면 두번째 요청의 응답이 다음과 같이 200응답이 회신된 것을 볼 수 있다. 유저를 삭제하는 URL과 CSRF토큰 값을 볼 수 있다. 

![두 번째 요청 200응답 확인](/images/burp-academy-host-header-6-7.png)

6. carlos 유저를 삭제하는 POST 요청을 만들어서 보낸다. 302 응답이 회신된다. 

![carlos 유저 삭제 요청 전송](/images/burp-academy-host-header-6-8.png)

7. 조금 기다리면 문제 풀이에 성공했다는 메세지가 출력된다. 

![풀이 성공](/images/burp-academy-host-header-6-success.png)

