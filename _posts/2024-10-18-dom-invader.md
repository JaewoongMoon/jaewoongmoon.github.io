---
layout: post
title: "Dom Invader 사용방법 정리"
categories: [취약점스캔툴, Burp Suite, Dom Invader]
tags: [취약점스캔툴, Burp Suite, Dom Invader]
toc: true
last_modified_at: 2024-10-18 21:55:00 +0900
---


# 개요
Dom Invader의 사용방법을 정리해둔다. Dom Invader를 사용하면 Dom 관련 취약점을 찾는 작업에 듣는 수고를 꽤 줄여준다. `Dom-XSS` 나 `Prototype Pollusion`, `Dom Clobbering` 등의 취약점을 찾아준다. 

# 기동방법
- Burp에 미리 설치된 Embeded Chrome을 실행해야 한다. (일반적인 Chrome에 확장 프로그램을 설치하는 방법은 제공하고 있지 않다.)
- Burp Suite 를 기동하고 Proxy > Intercept > Open Browser 버튼을 클릭하면 내장된 크롬 브라우저가 기동된다. 

# 사용방법

## 공통 설정
- 브라우저에서 화면 오른쪽 위의 Extension버튼을 눌러서 Settings에 들어간다.
- "DOM Invader in on" 을 켠다. 


## Dom-XSS 수동검출
기본적으로는 Dom Invader를 켠 상태에서 Web사이트를 조작하면 된다. 

- 페이지의 기능을 사용한다. Dom Invader 탭에서 Inject URL params를 선택한다. 
- URL Param에 페이로드가 설정된 새로운 탭이 열린다. (3번에서 URL 파라메터가 특정되었다면 그 파라메터를 사용한다. 특정되지 않으면 x와 같은 랜덤한 파라메터가 사용된다)

검출 예는 다음과 같다. Burp Academy 에서 파라메터를 포함한 URL로 접근하면 다음과 같이 알려준다. 

ex) 
https://{LAB-ID}.web-security-academy.net/?search=%22%2F%3Esync

![](/images/dom-invader-dom-xss-sink.png)


## Dom-XSS 자동검출
- Misc에서 "Inject canary into all sources is on"을 켠다. (주의:부하가 매우 커진다)
- 페이지의 기능을 사용한다. 그러면 그 것에 반응하여 Dom Invader가 체크를 시작한다. 

 "Inject canary into all sources is on" 옵션을 켜면 페이지 로드에 에러가 발생하는 경우도 있다. 이럴 때는 일단 끈 상태에서 페이지를 로드하고, 그 뒤에 옵션을 켜서 웹 페이지의 기능을 사용한다. 

## Postmessage
웹 메세지를 통해 Dom-XSS가 가능해지는 경우도 있다. 웹 메시지를 테스트하려면 Postmessage interception is on을 체크한다. 

![](/images/dom-invader-dom-xss-web-message-config.png)

## Dom clobbering & Prototype Pollusion
Attack Types에서 각각 Dom clobbering 과 Prototype Pollusion 체크를 활성화할 수 있다. 두 기능은 토글로 동작한다. 즉, 어느한쪽을 체크하면 다른 한쪽으로 체크가 해제된다. 

![](/images/dom-invader-dom-prototype.png)


 # 참고 
 - 오래된 정보긴 하지만 참고는 된다: https://speakerdeck.com/okuken/dom-invader?slide=25