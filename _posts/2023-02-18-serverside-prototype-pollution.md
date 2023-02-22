---
layout: post
title: "Burp Academy-서버사이드 프로토타입 오염(Server-side prototype pollution) 개념"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, 서버사이드 프로토타입 오염, Server-side prototype pollution]
toc: true
---

# 개요
- PortSwigger사의 [서버사이드 프로토타입 오염(Server-side prototype pollution)](https://portswigger.net/web-security/prototype-pollution/server-side){:target="_blank"} 을 보고 정리한 문서입니다. 

# 서버 사이드 프로토타입 오염(Server-side prototype pollution)
- Node.js와 같은 기술의 등장으로 자바스크립트는 이제 서버 백 엔드 개발에서도 널리 쓰이는 언어가 됐다. 
- 이 것은 자연히 `프로토타입 오염`이 백엔드 영역에서도 발생할 수 있는 취약점이 되었다는 것을 말한다. 
- 기본적인 핵심 컨셉은 클라이언트 사이드 프로토타입 오염과 동일하지만 몇 가지 어려운 점이 있다. 
- 이 문서에서 `서버 사이드 프로토타입 오염`에 대한 몇 가지 블랙박스 탐지 기법을 배울 것이다. 

# 왜 서버사이드 프로토타입 오염은 더 찾기 어려운가?
몇 가지 이유때문에 서버 사이드는 클라이언트 사이드보다 찾기 어렵다. 

- No source code access: 클라이언트 사이드와는 다르게 취약한 자바스크립트 코드를 볼 수 없다. 
- Lack of developer tools: 자바스크립트가 리모트 시스템에서 동작하고 있기 때문에 브레이크 포인트 등을 찍어서 디버깅하면서 오브젝트의 값을 확인할 수 없다. 
- The DoS problem: 성공적으로 

