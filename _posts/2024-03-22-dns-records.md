---
layout: post
title: "DNS 레코드 정리"
categories: [DNS]
tags: [DNS]
toc: true
last_modified_at: 2024-03-22 09:50:00 +0900
---

# 개요
DNS의 리소스 레코드를 정리해둔다. 


# NS 리소스 레코드
- 여기에 위임정보를 적는다. 
- 부모 Zone과 자식 Zone에 동일하게 적을 필요가 있다. 

다음과 같은 식이다. 

```
example.jp.             IN NS        ns1.example.jp.
example.jp.             IN NS        ns2.example.jp.
```



# SOA 리소스 레코드
- Zone의 정점에 적는 리소스 레코드이다. 
- SOA는 Start of Authority의 약어로 여기서부터 새로운 권위(Authority)가 시작됨을 의미힌다. 

다음과 같은 형태를 가진다. 

```
example.jp.            IN SOA    (
       ns1.example.jp.                  ; MNAME
       postmaster.example.jp.           ; RNAME
       2018013001                       ; SERIAL
       3600                             ; REFRESH
       900                              ; RETRY
       604800                           ; EXPIRE
       3600                             ; MINIMUM  
)
```

1. MNAME: 프라이머리 서버의 호스트명이다. 
2. RNAME: 존 관리자의 메일 주소이다. 
3. SERIAL: 존 데이터의 시리얼 번호다. 세컨더리 서버가 자신이 가진 존 데이터와 비교할 때 사용한다. 
4. REFRESH: 세컨더리 서버가 존 데이터의 갱신을 자발적으로 시작할 때의 시간이다.
5. RETRY: 존 데이터의 갱신에 실패했을 때 다시 시도할 때까지 기다리는 시간이다.
6. EXPIRE: 존 데이터의 갱신 실패가 계속되어 EXPIRE에 지정된 시간(초)동안 (위의 설정상으로는 7일이다.)  기다려도 성공하지 못했을 경우, 그 존 데이터는 유효기한이 지난 것으로 취급한다. 
7. MINIMUM: 존재하지 않는다는 정보(네거티브 캐시)를 저장하는 기간(TTL)이다.


# 참고
- 