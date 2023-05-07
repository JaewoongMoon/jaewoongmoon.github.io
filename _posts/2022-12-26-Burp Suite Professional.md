---
layout: post
title: "Burp Suite 팁 모음"
categories: [취약점 진단]
tags: [취약점 진단, Burp Suite]
toc: true
---

# Recorded Login 
- 테스트하는 방법 
https://portswigger.net/burp/documentation/desktop/scanning/recorded-logins


# 로컬호스트 스캔하기 
- 프록시 서버가 존재하는 사내 네트워크 내에서 Burp Suite를 기동하면 업스트림 프록시가 자동으로 설정되어 있다. 
- 이 상태에서 localhost를 스캔하려고 하면 통신이 프록시 서버로 향하게 되어 스캔이 제대로 실행되지 않는 경우가 있다. 
- 이런 경우에는 설정 > Network > Connections > Upstream proxy servers 에서 업스트림 프록시서버가 선택되어 있는 것을 해제하고 다시 스캔하면 된다. 