---
layout: post
title: "Burp Academy-Host 헤더 관련 취약점: Routing-based SSRF"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Host헤더]
toc: true
last_modified_at: 2023-12-11 09:50:00 +0900
---

# 개요
- HTTP Host 헤더 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/host-header/exploiting/lab-host-header-routing-based-ssrf
- 취약점 설명페이지 1: https://portswigger.net/web-security/host-header
- 취약점 설명페이지 2: https://portswigger.net/web-security/host-header/exploiting#routing-based-ssrf
- 난이도: PRACTITIONER (보통)

# 취약점 개요 (Routing-based SSRF)
- DMZ에 위치한 서버는 인터넷에서의 요청을 받고 뒤에 있는 백엔드 서버에게 요청을 전달해주는 역할을 하는 경우가 있다. 
- 해커 관점에서 보면 DMZ에 위치한 서버는 인터넷에서 요청을 보낼 수 있고, 조직 내부에까지 요청이 전달된다는 점 때문에 주요 공격 대상이 된다. 
- 공격에 성공하면 조직 내부의 서버에 접근할 수 있기 때문이다.
- DMZ의 서버에 설정 미스와 같은 취약점이 있으면 SSRF 공격이 가능하다. 

# 랩 개요
- 이 랩은 호스트헤더 인젝션을 통해 routing-based SSRF가 가능하다 .
- 이 것을 이용해 인터널 IP 주소 영역(192.168.0.0/24 )에 존재하는 관리자 패널에 접근해서 carlos유저를 삭제하면 문제가 풀린다. 

```
This lab is vulnerable to routing-based SSRF via the Host header. You can exploit this to access an insecure intranet admin panel located on an internal IP address.

To solve the lab, access the internal admin panel located in the 192.168.0.0/24 range, then delete the user carlos.
```

# 풀이 
1. 일단 랩 설명에서 admin 패널은 `192.168.0.0/24` 레인지에 존재한다고 되어 있다. 192.168.0.1부터 192.168.0.255중에 하나인 것이다. 이를 테스트하는 것은 Intruder를 사용하면 편하다. 다음과 같이 설정해준다. 어택 타입은 Sniper로, Host헤더의 마지막 옥텟을 Payload로 지정한다. Update Host header to match target은 반드시 체크를 해제해준다. (해제하지 않으면 Host헤더가 바뀌지 않는다.)

![Burp Intruder세팅](/images/burp-academy-host-header-4-1.png)

페이로드 타입은 숫자(Numbers)로 1부터 255까지를 지정한다. 

![Burp Intruder 페이로드](/images/burp-academy-host-header-4-4.png)

2. 공격을 시작하면 하나의 IP주소에서만 200응답이 있는 것을 볼 수 있다. admin패널이 있는 IP주소다. 응답을 보면 CSRF토큰 값과 유저 삭제 경로가 보인다. 

![Burp Intruder결과](/images/burp-academy-host-header-4-2.png)

3. POST요청으로 carlos유저를 삭제한다. 성공하면 302응답이 회신된다. 

![carlos유저삭제](/images/burp-academy-host-header-4-3.png)

4. 풀이에 성공했다는 메세지가 출력된다. 

![풀이성공](/images/burp-academy-host-header-4-success.png)