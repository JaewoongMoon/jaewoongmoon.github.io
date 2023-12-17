---
layout: post
title: "Burp Academy-Host 헤더 관련 취약점: Web cache poisoning via ambiguous requests"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Host헤더]
toc: true
last_modified_at: 2023-12-07 09:50:00 +0900
---

# 개요
- HTTP Host 헤더 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/host-header/exploiting/lab-host-header-web-cache-poisoning-via-ambiguous-requests
- 취약점 설명페이지 1: https://portswigger.net/web-security/host-header
- 취약점 설명페이지 2: https://portswigger.net/web-security/host-header/exploiting#accessing-restricted-functionality
- 난이도: PRACTITIONER (보통)

# 취약점 개요
- 웹 캐시에는 캐시 키(Cache Key)라는 개념이 있다. 유저로부터의 요청이 자신이 캐시하고 있는 요청과 동일한 요청인지를 판단하고, 동일한 요청이라면 백엔드 서버에 요청을 보내지 않고 캐시한 요청에 대한 응답을 유저에게 회신한다. 
- 웹 캐시는 HTTP요청 중 몇 가지를 기준으로 동일한 요청인지를 판단한다.
- 이 기준은 보통 Host 헤더나 요청 패스등이다.
- 호스트 헤더 인젝션으로 특정 요청을 캐싱시킬 수 있다면 웹 캐시 포이즈닝 공격으로 불특정 다수의 유저를 공격할 수 있다. 

# 랩 개요
- 이 랩은 캐시 서버와 백엔드 서버가 애매한 요청(ambiguous requests)을 처리하는 동작이 다르기 때문에 웹 캐시 포이즈닝이 가능하다. 
- 웹 캐시를 오염시켜서 홈 페이지를 방문한 유저에게 `alert(document.cookie)`를 실행시키면 문제가 풀린다. 

```
This lab is vulnerable to web cache poisoning due to discrepancies in how the cache and the back-end application handle ambiguous requests. An unsuspecting user regularly visits the site's home page.

To solve the lab, poison the cache so the home page executes alert(document.cookie) in the victim's browser.
```

# 풀이 시도 
1. 이번 문제는 exploit서버가 주어져 있다. `alert(document.cookie)`코드를 포함하는 exploit서버의 응답을 캐시시킬 수 있다면 문제가 풀릴 것이다. 

![exploit서버](/images/burp-academy-host-header-3-1.png)

2. 서버 응답 헤더는 다음과 같다. 캐시 컨트롤 헤더 `Cache-Control: max-age=30` 를 보아 백 엔드 서버가 이 요청을 캐싱하도록 하고 있는 것을 알 수 있고, `X-Cache: miss` 를 보면 이 요청이 웹 캐시에는 존재하지 않은 것을 알 수 있다. 그리고 동일한 요청을 다시 보내보면 `X-Cache: HIT` 헤더가 회신되는 것을 볼 수 있다. 웹 캐시가 사용되고 있는 것을 알 수 있다. 

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Cache-Control: max-age=30
Age: 0
X-Cache: miss
Connection: close
Content-Length: 10947

```

3. Host헤더를 직접 수정하는 방법은 안통하는 것 같다. Host헤더를 수정하면 504 Gateway Timeout이 회신된다. 

```http
HTTP/1.1 504 Gateway Timeout
Content-Type: text/html; charset=utf-8
Connection: close
Content-Length: 202

<html><head><title>Server Error: Gateway Timeout</title></head><body><h1>Server Error: Gateway Timeout (1) connecting to 0ae600a70435f3fd812d3f6100250007.h1-web-security-academy.net/e</h1></body></html>
```

4. 캐시 포이즈닝 가능한 조건을 찾아본다. `X-Forwarded-Host`헤더를 보내본다. 
포이즈닝이 안되는 것 같다. 기타 `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded`등도 시도해봤으나 포이즈닝되는 것 같지 않다. 

```http
X-Forwarded-Host: https://exploit-0a3600d70422f30281913ee20107002d.exploit-server.net/exploit
X-Host: https://exploit-0a3600d70422f30281913ee20107002d.exploit-server.net/exploit
X-Forwarded-Server: https://exploit-0a3600d70422f30281913ee20107002d.exploit-server.net/exploit
X-HTTP-Host-Override: https://exploit-0a3600d70422f30281913ee20107002d.exploit-server.net/exploit
Forwarded: https://exploit-0a3600d70422f30281913ee20107002d.exploit-server.net/exploit
```

5. ParamMiner라는 확장프로그램을 써본다. 포이즈닝될 것 같은 헤더를 자동으로 찾아준다고 한다. 진행황은 Logger탭에서 확인할 수 있고, 뭔가 발견되면 Dashboard에 스캔 Issue로 보고해준다고 한다. 이건 Burp Suite Pro버전일 때고, 커뮤니티 버전이라면 Extender->Extensions->Param Miner->Output에서 결과를 확인할 수 있다. 

![paramMiner실시](/images/burp-academy-host-header-3-2.png)

6. ParamMiner, 생각보다 시간이 걸린다. 그리고 결과도 헤더 포이즈닝 되는 것을 찾아주지 못했다. 모르겠다. 답을보자. 

# 답보고 풀이
7. 포인트는 Host헤더를 두 개를 넣는 것이었다! 😲 Host헤더가 두 개 있으면 `/resources/js/tracking/js` 자바스크립트 링크의 도메인이 두번째 Host헤더의 도메인으로 바껴서 응답된다.

![더블Host헤더테스트](/images/burp-academy-host-header-3-3.png)

8. 두 번째 Host헤더를 없앤 상태에서 다시 요청을 보내보자. 그러면 7번의 요청이 캐시되어 자바스크립트 링크의 도메인이 여전히 두 번째 Host헤더에 설정한 도메인으로 되어 잇는 것을 확인할 수 있다. 

9. exploit 서버를 구성한다. `/resources/js/tracking/js` 로 요청이 들어오면 `alert(document.cookie)` 가 동작하도록 만든다. 

![exploit서버구성](/images/burp-academy-host-header-3-4.png)

10. 잠시 시간이 지나면 풀이에 성공했다는 메세지가 출력된다. (랩에서 유저의 동작이 시뮬레이션 되고 있기 때문에 가만히 있어도 풀린다.)

![풀이성공](/images/burp-academy-host-header-3-success.png)