---
layout: post
title: "칼리리눅스 Purple"
categories: [칼리리눅스]
tags: [칼리리눅스, Purple]
toc: true
last_modified_at: 2025-04-28 09:33:00 +0900
---


# 개요
방어자 관점에서 사용할 수 있는 칼리 리눅스 버전으로 'Purple'이 있다. 2023년에 릴리즈 되었다. 

# Kali Purple 개요
Kali Purple은 Defensive Security를 위한 것이다. 
- 100여개의 방어용 도구들을 포함 : Arkime, Cyberchef, Elasticsearch SIEM, GVM 취약점 스캐너, Malcolm, Suricata/Zeek IDS 등
- NIST CSF를 따르는 방어 메뉴 구성 : Identify, Protect, Detect, Respond, Recover
- 궁극적인 SOC In-A-Box를 구성하기 위한 레퍼런스 아키텍처
- Kali Autopilot - 자동 공격을 위한 공격 스크립트 빌더/프레임워크

공식 문서를 보면 'Kali Purple SOC In-A-Box' 라고 해서, 관련 서버(SW)들을 하나의 SOC(Security Operation Center)로 묶어서 설치하는 것을 안내하고 있다. 역할에 따라 다음과 같이 구성된다. 구성요소는 다음과 같다. 

|단계|관련모듈명|설명|비고|
|---|-----|-----|------|
|100 - IDENTIFY| Kali-Viloet|CTI(Cyber Threat Intelligence)용 서버|
|200 - PROTECT| Byzantium|방어용 서버. IDS/IPS, Firewall등이 설치되어 있다.|
|300 - DETECT|Kali-Purple|SIEM으로 Elastic Search 가 설치되어 있다.|
|400 - RESPOND|Kali-Eminence|다양한 조사용툴-포렌식툴-이 설치되어 있는 서버|
|500 - RECOVER|||
|1000 - OTHERS|Kali-Heliotrope|클라이언트 머신|
|1000 - OTHERS|Kali-Pearly|DVWA(Damn Vulnerable Web Application)이 설치된 서버|


# 설치 방법
다음 두 곳에서 환경 구성 파일을 서비스하고 있었다. 

- Terraform 버전: https://github.com/tayontech/kali-soc-terraform?tab=readme-ov-file
- AWS CloudFormation 버전: https://github.com/ZoccoCss/kalisoc

# 참고
- https://news.hada.io/topic?id=8719
- https://pstor-kr.tistory.com/407
- Kali Purple 공식 문서: https://gitlab.com/kalilinux/kali-purple/documentation/-/wikis/home
- Kali Purple 리뷰 유튜브 (Snyk을 광고하고 있다!): https://www.youtube.com/watch?v=4O2p_WnAH10 