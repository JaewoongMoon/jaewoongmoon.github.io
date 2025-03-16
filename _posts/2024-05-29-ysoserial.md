---
layout: post
title: "ysoserial 사용법"
categories: [보안취약점, Insecure Deserialization]]
tags: [보안취약점, Insecure Deserialization]
toc: true
last_modified_at: 2024-06-20 21:00:00 +0900
---


# 개요
- 외국의 유튜버가 만든 ysoserial 소개 영상을 보면 발음은 "와이-소-시리얼"로 하는 것을 볼 수 있다. ("이-소-시리얼"이 아니었다!)
- 조커의 "Why so serial?" 를 패러디한 것이 확실하다. 

![](/images/ysoserial.png)

# 기본 사용법

```sh
java -jar ysoserial-all.jar [페이로드명] '[삽입할 커맨드]'
```

예) Burp Academy에서 사용했던 예 

```sh
java -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt'
```


# 타겟에 어떤 페이로드를 사용할 수 있는지 어떻게 판단하는가?
- 기본적으로는 타켓(조사대상)의 밖으로 노출된 부분, 예를 들면 쿠키 값이나 어떤 입력폼의 값이 직렬화되어 있는 경우 (보통 base64인코딩 되어 있는 경우가 많다), 이 것의 텍스트값에 Java 클래스명이 보이거나 한다. CommonCollections와 같은 문자열이다. 이 것을 보고 CommonCollections에 대한 페이로드를 사용하는 것을 판단할 수 있다.


# 유용한 페이로드
ysoerial에서 제공하는 모든 페이로드가 커맨드 인젝션을 수행하는 것은 아니다. 예를 들면 탐지(Detection)목적으로 사용하기에 적절한 페이로드도 있다. 다음 두 가지다. 

## URLDNS 
URLDNS 체인은 제공된URL에 대한 DNS lookup을 유발(trigger)시킨다. 이 것은 Burp Collarator서버와 협업해서 취약점을 체크할 수 있다는 말이다. 

## JRMPClient 
JRMPClient 체인은 도메인 대신에 IP주소를 입력받는다. IP주소에 대한 TCP 커넥션을 수립하는 것을 유발시킨다. 이 체인은 DNS lookup을 포함해 아웃바운드 통신을 파이어월이 모두 블록하는 경우에 유용하다. 테스트시에는 로컬 IP주소와 인터넷IP주소를 사용할 수 있다. 로컬IP주소를 사용하는 경우에는 바로 응답이 오지만 인터넷IP주소를 사용하는 경우 응답이 오지 않거나 지연되는 경우, 이 개짓체인이 작동되고 있다고 볼 수 있다. 타겟 서버가 블록된 IP주소에 대해 연결을 시도하고 있다는 것이기 때문이다. 

# 참고 
- https://github.com/frohoff/ysoserial
- https://frohoff.github.io/appseccali-marshalling-pickles/
- https://medium.com/abn-amro-red-team/java-deserialization-from-discovery-to-reverse-shell-on-limited-environments-2e7b4e14fbef
- https://portswigger.net/web-security/deserialization/exploiting