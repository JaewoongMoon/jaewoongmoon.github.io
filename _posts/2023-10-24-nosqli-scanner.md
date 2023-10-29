---
layout: post
title: "Burp Crawling 사양 정리"
categories: [취약점스캐너, Burp Suite]
tags: [취약점스캐너, Burp Suite]
toc: true
last_modified_at: 2023-10-25 09:15:00 +0900
---

# 개요
- 2023년 10월 25일 기준, Burp Suite의 기본 스캐너로는 NoSQL 인젝션을 탐지하지 못한다.
- Burp Suite 확장 프로그램인 NoSQL 인젝션 스캐너 "Burp NoSQLi Scanner"를 사용해보고 사용법과 결과등을 정리해둔다. 
- 스캔대상은 [여기]()에서 구축했던 서버를 대상으로 한다. 

# 설치 
BApp 스토어에서 설치하면 된다. 

![Burp NoSQLi Scanner설치](/images/nosqli-practice-install-nosqli-scanner.png)

# 사용법
- 공식 사이트에는 사용법이 따로 적혀있지 않다. 
- 예전에 Log4Shell 스캐너 확장 프로그램을 사용했을 때의 경험을 바탕으로 동일한 순서로 스캔해주었더니 스캔이 되었다. 
- scan launcher의 Scan Configuration 메뉴에서 Select from library를 선택하고, Audit checks - extensions only를 선택해주면 된다. 이렇게 하면 확장 프로그램에서 제공하는 스캔 기능만을 사용해서 스캔할 수 있다. 

![Configuration선택하기](/images/nosqli-practice-nosqli-scanner-configuration.png)

# 스캔 결과 
스캔 결과는 다음과 같다. NoSQL인젝션이 되는 것을 검출해주었다. 

![스캔 결과1](/images/nosqli-practice-nosqli-scanner-result-1.png)

![스캔 결과2](/images/nosqli-practice-nosqli-scanner-result-2.png)

# 참고 
- https://github.com/matrix/Burp-NoSQLiScanner
- https://github.com/matrix/Burp-NoSQLiScanner/blob/main/src/burp/BurpExtender.java
- https://github.com/codingo/NoSQLMap