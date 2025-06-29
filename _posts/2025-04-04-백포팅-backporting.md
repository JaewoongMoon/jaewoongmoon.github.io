---
layout: post
title: "백포팅 관련 정보 정리"
categories: [리눅스, 미들웨어, 취약점]
tags:  [리눅스, 미들웨어, 취약점, 백포팅]
toc: true
last_modified_at: 2025-04-04 21:55:00 +0900
---


# 개요 
취약점 대응시 참고해야 하는 "백포팅(Back porting)" 개념에 대해 정리해둔다. 

# 백포팅이란?
- 오픈소스SW의 취약점을 판별할 때 해당 SW의 버전이 알려진 취약점 정보(CVE정보)에 취약하다고 적혀있는 버전인지 아닌지로 판단하는 방법을 사용한다. 
- 그런데 어떤 리눅스 배포판에서는 취약하다고 알려진 버전인데도, 실제로는 취약점이 존재하지 않는 경우가 있따. 
- 리눅스 개발측에서 따로 버전 관리를 하기 때문이다. (이 것을 메인티넌스 버전이라고 부르기도 한다.)
- 예를 들어 Apache같은 웹서버의 2.4.6에 특정 취약점이 있다고 하자. 레드햇이나 우분투같은 리눅스에서는 동일한 2.4.6이라도 취약점이 있을 수도 있고 없을 수도 있다. 
- 이게 보안 엔지니어 입장에서는 골치아픈 부분이다. 체크해야할 포인트가 늘어나기 때문이다. 

# 백포팅을 확인해야 하는 배경 
주로 특정 서버에 대해서 취약점을 스캔한 결과를 토대로 정말 취약한 버전인지를 판단하고 싶을 때 사용한다. 취약점 스캐너는 외부에서 보이는 정보를 토대로 그에 해당하는 취약점을 모두 열거하는 식으로 동작한다. 예를 들면, 취약점 스캔을 했는데 어떤 아파치 서버가 버전 2.4.6으로 보여서, CVE 데이터베이스 상에서 아파치 서버 버전 2.4.6이 해당되는 모든 취약점이 있다고 보고하는 식이다. 그런데 실제로는 스캔 대상 서버가 레드햇OS로 구동되고 있고, 아파치 2.4.6서버는 레드햇에서 관리하는 메인티넌스 버전의 서버일 수 있는 것이다. 

# Apache 2.4.x 의 취약점 대응 이력
일단 공식적인 Apache 서버 개발팀의 취약점 대응상황을 확인해야 한다. 오픈소스 Apache의 취약점 대응상황은 다음 두 가지 방법을 확인할 수 있다. 

- 버전2.4x에서 대응한 취약점 전체목록을 보고싶을 떄: https://httpd.apache.org/security/vulnerabilities_24.html
- 특정 버전에서 어떤 CVE를 대응했는지 확인하고 싶을 때: https://archive.apache.org/dist/httpd/ 에 방문해서 CHANGES_{version} 파일의 Last Modified 시각과 내용을 확인한다. 

# 각 리눅스 배포판에서 취약점 대응 상황 확인
각 리눅스 배포판에서 어떻게 대응하고 있는지를 확인한다. 

|Linux배포판|URL|설명|
|----------|----|---|
|Redhat|https://access.redhat.com/errata-search/|CVE번호로 검색하는 것으로 대응했는지 여부를 알 수 있다.|
|Ubuntu|https://ubuntu.com/security/cves|CVE번호로 검색하는 것으로 대응했는지 여부를 알 수 있다.|


# 각 리눅스 배포판에서 Apache 서버2의 메인티넌스 버전 확인
각 리눅스 배포판에서 Apache 서버2의 메인티넌스 버전을 확인하는 법을 정리해둔다. 보안 엔지니어 입장에서는 이 버전이 최신버전이니 업데이트 해주세요라고 서버관리측에 말할 경우에 사용할 수 있다. 서버 관리측에서는 취약점 스캔 결과가 참인지 거짓인지 판별하는 용도로 사용할 수 있다. 

## 레드햇
- https://access.redhat.com/solutions/445713: 레드햇에서 Apache2 서포트 상황을 볼 수 있다. 
- https://access.redhat.com/downloads/content/package-browser: 로그인이 필요하다. 레드햇의 Apache2 메인티넌스 버전을 확인할 수 있다. 

## 우분투
- https://launchpad.net/ubuntu/+source/apache2: 우분투 OS버전 별 Apache2의 최신버전을 확인할 수 있다. 
- https://launchpad.net/ubuntu/+source/apache2/+publishinghistory: 우분투 OS버전 별 Apache2의 릴리즈 이력을 확인할 수 있다. (스캔 대상 서버의 OS가 우분투인 것을 알고 있을 때, Apache버전이 어느시기에 릴리즈된 버전인지, 즉 오래되었는지 아닌지를 확인할 때 유용하다)

# Nessus 스캐너의 백포트 대응
Nessus 스캐너는 백포트 정보를 파악하고 있어서, 만약 취약점이 백포팅을 통해 메인티넌스 버전에서 대응하고 있다고 판단되면 스캔 결과에서 제외해주는 멋진 기능을 갖고 있다. Nessus 설치폴더에 있는 'backport.inc' 파일에는 겉으로 보이는 서버 배너 정보와 실제버전에 대한 매핑정보가 있어서 이 정보를 통해 판단한다. 이에 대한 상세한 내용은 다음 페이지를 참고 한다. 

- https://community.tenable.com/s/article/Apache-Vulnerabilities-and-Backported-Patching?language=en_US
- https://community.tenable.com/s/article/How-does-Nessus-Handle-Backported-Patches?language=en_US


그런데 이 기능과 관련해서 한 가지 주의할 점도 있다. OS버전 판단이 잘못되면 결과가 틀릴 수도 있다는 점이다. OS버전에 따라 SW의 메인티넌스 버전도 달라지기 때문이다. 

혹시 이 기능을 끄고 싶다면 Nessus에서 Settings > Accuracy > Override normal accuracy 의 Avoid potential false alarms 를 체크해주면 된다. 

# 참고 
- 레드햇 백포팅 설명: https://access.redhat.com/security/updates/backporting/
- 백포팅을 설명하는 일본어 블로그: https://ashanoguzyutu.hatenablog.com/entry/2019/07/15/171417