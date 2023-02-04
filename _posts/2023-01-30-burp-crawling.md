---
layout: post
title: "Burp Crawling 사양 정리"
categories: [취약점스캐너, Burp Suite]
tags: [취약점스캐너, Burp Suite]
toc: true
---

# 개요 
- [https://portswigger.net/burp/documentation/scanner/crawling](https://portswigger.net/burp/documentation/scanner/crawling) 의 크롤링 사양을 보고 정리한다. 


# Core approach 
가능한한 실제에 가까운 어플리케이션 구조를 파악하도록 다양한 테크닉이 사용되고 있다. 
- Burp의 내장 브라우저를 사용해서 크롤링한다. 
- 링크를 클릭하거나 입력폼 등을 제출하면서 정보를 수집해간다. 
- 시작지점부터해서 방향이 있는 그래프(direct graph)를 만들어간다. 
- 크롤러는 Location에 대해 URL 구조를 보고 판단하지 않는다. 대신에 컨텐츠를 기반으로 판단한다. 
- 이는 URL이 완전히 동일하더라도 내용이 달라지는 페이지등에 대해서도 문제없이 크롤링을 수행한다는 것을 말한다. 

# Session handling
대략 다음과 같은 사양이다. 꽤 우수하다. 
- Burp의 크롤러는 내장된 브라우저를 사용해 크롤링을 수행한다 .
- 모던 브라우저가 가지고 있는 세션 핸들링 기능을 동일하게 가지고 있다. 
- Burp 크롤러는 복수의 에이젼트를 실행시켜 크롤링을 수행한다. 
- 각 에이전트는 별도의 cookie 저장공간(jar)을 가지고 있어서 새로운 쿠키를 발급받으면 거기에 저장한다. 
- 직전의 서버 응답을 참고해서 다음 크롤링을 수행하기 때문에 CSRF 토큰등을 자동으로 대응하면서 크롤링할 수 있다. 

# Detecting changes in application state
크롤링중에 어플리케이션 상태가 변경되더라도 어느 액션으로 인해 변경된 것인지 판단가능하다. 


# Application login 
- 크롤러는 인증되지 않은 상태에서부터 크롤링을 시작한다. 
- 로그인이 가능한 곳이나 유저 등록이 가능한 곳을 찾으면 시도한다. 

# Crawling volatile content
페이지에 일시적으로 나타나는 컨텐츠도 파악가능하다. (일시적인 부분을 제거한 나머지 부분으로 유니크 로케이션을 판단하는 것 같다.)

# Crawling with Burp's browser (browser-powered scanning)
- 디폴트 옵션이면, Burp 내장 브라우저가 사용가능하다면 이 브라우저를 사용해서 크롤링을 수행한다. 
- 자바스크립트로 쓰여진 복잡한 이벤트 핸들러 등에 대해서도 잘 동작한다. 