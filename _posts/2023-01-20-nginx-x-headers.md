---
layout: post
title: "Nginx 프록시 관련 헤더 정리"
categories: [HTTP 헤더, Nginx]
tags: [HTTP 헤더, Nginx, 프록시 헤더]
toc: true
---

# 개요 
Nginx에서 `X-` 가 포함된 프록시 관련 헤더는 뭐하는 헤더인지 정리해본다. 
주로 자주 보이는 헤더는 다음과 같은 헤더이다. 

```
     proxy_set_header Host             $host;
     proxy_set_header X-Real-IP        $remote_addr;
     proxy_set_header X-Forwarded-For  $proxy_add_x_forwarded_for;
     proxy_set_header X-Forwarded-User $remote_user;
     proxy_set_header X-Forwarded-Proto $scheme;

```

# Host 헤더 
- Host 헤더는 HTTP 요청을 보내는 쪽에서 붙이는 헤더이다.
- 어떤 도메인/포트의 서버에 접속하고 싶은지를 나타낸다. 
- HTTP 1.1 프로토콜의 헤더이다. (HTTP2 에서는 authority 헤더가 이 역할을 한다고 한다. )
- 주로 동일 IP에서 가상호스팅으로 여러개의 도메인이 운영되고 있는 서버에서 어느 도메인의 서버로 접속하려고 하는 요청인지 구별하기 위해서 사용되는 것 같다. 


# X-Real-IP
- HTTP 요청 클라이언트의 진짜 IP주소이다. (글로벌 IP주소)

# X-Forwarded-For
- https://developer.mozilla.org/ko/docs/Web/HTTP/Headers/X-Forwarded-For
- X-Forwarded-For(XFF) 헤더는 HTTP 프록시나 로드 밸런서를 통해 웹 서버에 접속하는 클라이언트의 원 IP 주소를 식별하는 사실상의 표준 헤더다.
- 클라이언트와 서버 중간에서 트래픽이 프록시나 로드 밸런서를 거치면, 서버 접근 로그에는 프록시나 로드 밸런서의 IP 주소만을 담고 있다. 
- 클라이언트의 원 IP 주소를 보기위해 X-Forwarded-For 요청 헤더가 사용된다.
- 이 헤더는 디버깅, 통계, 그리고 위치 종속적인 컨텐츠를 위해 사용되고, 클라이언트의 IP 주소 등과 같은 민감한 개인정보를 노출시킨다. 그러므로 이 헤더를 사용할 때에는 사용자의 프라이버시를 주의해야 한다.
- 현재 어떠한 표준 명세에도 속하지 않는다. 이 헤더의 표준화된 버전은 HTTP `Forwarded` 헤더다.

## 문법
```
X-Forwarded-For: <client>, <proxy1>, <proxy2>
```

## 예 
```
X-Forwarded-For: 203.0.113.195, 70.41.3.18, 150.172.238.178
```

# X-Forwarded-Host
- https://developer.mozilla.org/ko/docs/Web/HTTP/Headers/X-Forwarded-Host
- X-Forwarded-Host(XFH) 헤더는 HTTP 요청 헤더에서 클라이언트가 요청한 원래 Host 헤더를 식별하는 사실상의 표준 헤더이다. 
- 리버스 프록시(로드발란서, CDN) 에서 Host 이름과 포트는 요청을 처리 하는 Origin 서버와 다를 수 있다. 
- 이러한 경우 X-Forwarded-Host 헤더는 원래의 Host를 확인 하는데 유용하다. 
- 현재 어떠한 표준 명세에도 속하지 않는다. 이 헤더의 표준화된 버전은 HTTP `Forwarded` 헤더다.

## 문법
```
X-Forwarded-Host: <host>
```

## 예
```
X-Forwarded-Host: id42.example-cdn.com
```

# X-Forwarded-User
- Nginx 의 `$remote_user` 를 설정하는 경우, 이 것은 Basic 인증한 유저명을 가리킨다. 
- http://nginx.org/en/docs/http/ngx_http_core_module.html

# X-Forwarded-Proto
- http, https 등 HTTP 서비스 요청의 스킴(scheme) 부분이다. 

