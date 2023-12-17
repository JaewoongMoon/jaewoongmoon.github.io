---
layout: post
title: "Burp Academy-Host 헤더 관련 취약점: SSRF via flawed request parsing"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Host헤더]
toc: true
last_modified_at: 2023-12-11 09:50:00 +0900
---

# 개요
- HTTP Host 헤더 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/host-header/exploiting/lab-host-header-ssrf-via-flawed-request-parsing
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
This lab is vulnerable to routing-based SSRF due to its flawed parsing of the request's intended host. You can exploit this to access an insecure intranet admin panel located at an internal IP address.

To solve the lab, access the internal admin panel located in the 192.168.0.0/24 range, then delete the user carlos.
```

# 풀이 
1. 문제 4번과 마찬가지로 `/admin`엔드포인트에 대해 Host헤더의 값을 `192.168.0.0/24` 레인지로 설정하여 Intruder로 공격해보면 이번에는 모두 403 Forbidden응답이 회신된다. 뭔가 다른 테크닉이 필요한 것을 알 수 있다. 

2. `X-Forwarded-Host`, `X-Host`, `X-Http-Host-Override`, `Forwarded` 헤더도 페이로드로 설정해서 공격해본다. 이번에는 페이로드가 모두 일괄적으로 적용되도록 Attack Type을 Battering ram으로 변경한다. 

![Intruder 설정](/images/burp-academy-host-header-5-1.png)

3. 결과는 다음과 같다. 여전히 모두 403응답이다. Host헤더 외에 다른 비슷한 헤더를 추가하는 방법은 안 통하는 것 같다. 

![Intruder 공격 결과](/images/burp-academy-host-header-5-2.png)

4. 다른 방법을 생각해본다. 이번에는 HTTP요청의 경로부분에 URL절대경로를 지정하는 테크닉을 사용해본다. URL의 도메인과 Host헤더의 도메인이 동일하면 404응답이 회신된다. 

![URL절대경로 테스트결과 1](/images/burp-academy-host-header-5-3.png)

5. Host헤더를 내부 IP로 바꿔서 요청을 보내본다. 그러면 이번에는 `Server Error: Gateway Timeout (3) connecting to 192.168.0.1` 이라는 메세지가 응답된다. Host헤더에 지정한 내부 IP로 접속을 시도하려고 한다는 것을 알 수 있다. 이건 공격이 가능해보인다. 

![URL절대경로 테스트결과 2](/images/burp-academy-host-header-5-4.png)

(추후 정답을 보니 이 단계에서 Burp Collaborator를 사용하고 있었다. 위와 같은 힌트를 주는 서버 메세지가 없는 경우는 Burp Collaborator를 사용해도 되겠다. Burp Collaborator를 사용하면 더욱 확신을 가질 수 있다.)

6. Intruder로 다시 한번 테스트 해본다. IP주소를 페이로드로 설정한다. 

![Intruder 설정](/images/burp-academy-host-header-5-5.png)

그러면 이번에는 특정 페이로드에서 200응답이 확인된다! 이 IP주소를 지정하면 내부 서버에서만 접근가능한 admin패널에 접근이 가능하다. 

![Intruder 공격 결과](/images/burp-academy-host-header-5-6.png)

7. 메소드를 POST로 변경하고 `/admin/delete` 엔드포인트로 carlos유저 삭제하는 요청을 보낸다. 성공하면 302응답이 회신된다. 

![유저 삭제 요청](/images/burp-academy-host-header-5-7.png)

8. 랩 페이지를 리로드하면 풀이에 성공했다는 메세지가 표시된다. 

![풀이 성공](/images/burp-academy-host-header-5-success.png)