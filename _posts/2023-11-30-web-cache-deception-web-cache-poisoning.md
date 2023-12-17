---
layout: post
title: "Web Cache Poisoning 과 Web Cache Deception 의 차이"
categories: [웹 보안]
tags: [웹 보안]
toc: true
last_modified_at: 2023-11-13 09:50:00 +0900
---

# Web Cache Poisoning 과 Web Cache Deception 의 차이
- Web Cache Poisoning은 Web Cache를 속여서 어떤 공격을 하기위한 웹 페이지를 캐싱시켜 여기에 다른 사용자를 유도하는 방식의 공격이다.
- Web Cache Deception은 Web Cache를 속여서 사용자의 개인정보와 같은 민감한 정보가 캐싱되도록 만들어, 공격자는 캐싱된 페이지에 접근해 민감한 정보를 수집하는 방식의 공격이다. 

# Web Cache Deception 의 예
- [여기](https://hackerone.com/reports/593712)에 유명한 예가 있다. 
- 존재하는 않는 정적 컨텐츠 URL(예를들면 http://www.example.com/home.php/non-existent.css)로 접근하면 개인정보가 포함된 경로(예를들면 http://www.example.com/home.php 와 같은 톱 페이지)로 리다이렉트해주는 서버가 있다고 하면 이 서버는 Web Cache Deception이 가능하다. 
- 정적컨텐츠(css)에 대한 요청이므로 캐시 서버는 이 요청에 대한 응답을 캐시한다. 
- 공격자가 http://www.example.com/home.php 에 접근하면 직전에 접근한 다른 사용자의 정보를 볼 수 있다. 

# 참고 
- https://hacktricks.boitatech.com.br/pentesting-web/cache-deception