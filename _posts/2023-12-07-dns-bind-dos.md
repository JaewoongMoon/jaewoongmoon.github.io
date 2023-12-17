---
layout: post
title: "DNS Bind서버 Dos취약점"
categories: [취약점]
tags: [취약점,DNS]
toc: true
last_modified_at: 2023-11-13 09:50:00 +0900
---

# 개요
- DNS 서버 소프트웨어인 Bind 에 대해 Dos 공격을 할 수 있는 취약점을 정리해둔다. 
- Dos공격을 통해 DNS 서버가 다운되면 해당 DNS서버에서 관리하고 있는 도메인은 쿼리가 안되므로 해당 도메인에 접속하는데 아주 큰 지장이 생긴다. 
- 이 중에서 exploit코드가 알려진 취약점이 있는지도 알아본다. 

# 검색
- Bind에서 Dos가 가능한 취약점을 [CVE 목록](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=bind+dos)에서 찾아보면 2023년 12월7일 기준으로 11개가 검색된다. 

# 목록
이 취약점들은 모두 Metasploit에는 exploit코드가 존재하지 않았다. 
- CVE-2023-36368
- CVE-2023-22392
- CVE-2022-43171
- CVE-2016-6213
- CVE-2012-3429
- CVE-2012-2134
- CVE-2011-1745
- CVE-2005-2712
- CVE-2002-0651
- CVE-2002-0400
- CVE-2000-0887

## CVE-2000-0887
- DNS의 존 정보 전송 쿼리 중에 압축해서 보내는 타입인 ZXFR 과 관련이 있는 것 같다. 
- "ZXFR bug"라고도 불린다고 한다. 
- https://krevetk0.medium.com/dns-vulnerability-for-axfr-queries-58a51972fc4d
- 

# 참고 
- 
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-0887