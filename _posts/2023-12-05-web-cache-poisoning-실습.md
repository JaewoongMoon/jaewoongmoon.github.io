---
layout: post
title: "Web Cache Poisoning 실습"
categories: [웹 보안]
tags: [웹 보안]
toc: true
last_modified_at: 2023-12-05 09:50:00 +0900
---

# 개요
- 2018년에 실시했던 웹 캐시 포이즈닝 실습결과를 재정리한 문서이다. 
- Web Cache Poisoning 이란 프록시/리버스 프록시를 사용하는 환경에서 프록시 서버의 웹 캐시를 오염시키는 공격이다. 
- 오염된 캐시로 인해 일반 유저가 악의적인 사이트로 유도되어 피싱이나 드라이브 바이 다운로드 공격등을 당할 위험이 있다. 
- 가장 잘 알려진 공격 방법은 X-Forwarded-Host (XFH) 헤더를 이용하는 것이다. 
- 본래 XFH 헤더는 리버스 프록시 등을 사용하는 환경에서 유저가 어떤 서버에 대해 요청을 보냈는지 구분하기 위해 사용된다. 
- 웹 캐시가 사용되는 환경에서 악용되면 Web Cache Poisoning 공격이 성공한다. 

## 동향 
- 비교적 최근(2018년)에 많이 발견되고 있으며 아직 많이 알려진 공격은 아니다. 
- 취약한 미들웨어를 사용할 경우 어플리케이션에 취약점이 없어도 공격이 성공할 수 있다. 
- IBM, Amazon, Cisco, Apache Struts 등 다양한 벤더의 웹 서버나 프레임워크에 해당 취약점이 있는 것이 보고되고 있다.  (SA-CORE-2018-005 : drupal ,ZF2018-01 : zend(php framework), CVE-2018-14773 : symfony (php framework) )
- CVE 리스트 : https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=web+cache+poisoning

# 웹 캐시 포이즈닝 공격 시나리오
웹 캐시 포이즈닝 공격 시나리오는 다음과 같다. 

![공격 시나리오](/images/wcp-scenario.png)

프록시 서버는 웹 캐시 서버로 사용되고 있다. 

1. 공격자가 프록시 서버에 악의적인 페이로드(X-Forwarded-Host헤더를 공격자 서버 도메인으로 설정한 페이로드)를 보낸다. 
2. 프록시 서버는 공격자의 요청을 그대로 취약점 있는 웹서버에 전송한다. 
3. 웹서버(백엔드 서버)는 취약점이 있어서 X-Forwarded-Host 헤더의 값을 검증하지 않고 악의적인 사이트 (evil.com)으로 리다이렉트 시키는 302응답을 회신한다. 
4. 302응답을 받은 프록시 서버는 이 응답을 캐싱한다. (캐시가 오염된다.)
5. (캐시가 살아있는 동안) 사용자가 동일한 URL을 프록시 서버에 요청한다. 
6. 프록시 서버는 오염된 캐시를 사용자가에 회신하므로 이 사용자는 악의적인 사이트로 유도된다. 

# 테스트 환경 
## 네트워크 구성 
Virtualbox를 사용해서 다음 구성도대로 통신이 되도록 구성하였다. 

![네트워크구성](/images/wcp-network-diagram.png)

## 프록시 서버 
- 프록시 서버 프로그램은 squid 3.5.27 (2018년 기준 최신버전)를 사용하였다. 
- 테스트를 위해 캐싱되는 기간을 길게 설정하였다. 

### 설정 예

```sh
# 프록시 서버에 접근가능한 클라이언트 IP 대역 설정
acl localnet src 10.121.32.0/22 

# 프록시 서버에서 허용할 URL 설정
acl allow_urls dstdomain 10.121.35.160
http_access allow allow_urls

# 캐싱되는 최소 시간(minute)을 0 에서 500으로 변경 
refresh_pattern .               500    20%     4320
```

## 웹 서버 
- 웹 서버는  다음과 같은 페이지를 사용하였다. 
- HTTP 요청에 X-Forwarded-Host 헤더가 있으면 해당 헤더가 지정하는 값으로 리다이렉트된다. 

```java
<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<%
System.out.println("Call!! from : " + request.getRemoteAddr());

//302応答は、基本的に、プロキシサーバーがキャッシュしてない。
//次のキャッシュコントロールヘッダを追加すると、302応答であっても、プロキシサーバーにキャッシュされる。
response.setHeader("Cache-Control", "max-age=600, must-revalidate");

// x-forwarded-hostヘッダがあれば、そのホストにリダイレクトする。
String forward_host = request.getHeader("X-Forwarded-Host");
if(forward_host != null && !forward_host.equals("")){
	System.out.println("Client will be redirected to ... :" + forward_host);
	response.sendRedirect(forward_host);
}

%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Insert title here</title>
</head>
<body>
Hello Client!
You will be redirected to... 
</body>
</html>
```

## 공격자 환경 
- 공격자는 burpsuite 등의 로컬 프록시 툴을 사용해서 HTTP 헤더를 마음대로 변조할 수 있도록 구성하였다. 


# 검증 결과 
## 검증 과정 

다음과 같은 순서로 검증한 결과 공격이 성공하는 것을 확인했다.

공격자가 Web Cache Poisoning 페이로드(본 예제에서는 X-Forwarded-Host: evil-page.jsp)가 설정된 HTTP 요청을 보낸다. 

![웹캐시포이즈닝 시도](/images/wcp-x-forwarded-for-request.png)


다음과 같은 응답이 회신되었다. 이를 통해 공격자는 이 요청이 프록시 서버에 캐싱된 것을 알 수 있다. 

`X-Cache: HIT from xxxxxx`
`X-Cache-Lookup: HIT from xxxxxx`

![웹캐시포이즈닝 성공](/images/wcp-cached-302-response.png)

- X-Cache :프록시 서버의 캐시에서 이 요청에 대한 응답을 찾았는지 여부 (HIT/MISS)
- X-Cache-Lookup: 해당 요청에 대한 응답이 캐싱 가능했는지 여부 (HIT/MISS)

이 후 유저가 동일한 URL로 접속하면 다음과 같이 임의의 페이지(evil-page.jsp)로 리다이렉트된다. 

![일반유저에 대한 공격 결과](/images/wcp-redirected-and-hacked.png)

## 알게된 것 
- 웹 서버의 응답에 포함된 cache-control 헤더의 값에 따라 공격 성공여부가 결정되었다. 
- **웹 서버의 응답 헤더에 캐싱이 가능하도록 되어있는 경우(cache-control: max-age=600, must-revalidate)엔 공격이 성공하였고, 캐싱이 불가능한 경우(cache-control: no-cache) 는 공격이 실패하였다.**
- 웹 서버 응답에 아무런 cache-control 헤더가 없어도 공격이 실패하였다. 이 것은 백엔드 서버로 부터 받은 응답에 cache-control 헤더가 없는 경우 캐싱하지 않는 것이 squid 3.5.27 프록시의 기본 동작이기 때문인 것으로 보인다. 
- 다른 웹 캐시 서버에서는 웹 서버의 cache-control 헤더의 값에 관계없이 캐싱이 될 수도 있다. 

# 방어 방법 
## 웹 서버 / 웹 어플리케이션 
- 웹 서버는 취약점이 없는 최신의 프레임워크/웹 서버 프로그램을 사용한다.
- X-Forwarded-Host 응답이 필요없다면 해당 헤더에 반응하지 않도록 한다. 
- 반응할 필요가 있다면 신뢰할 수 있는 URL인 경우에만 응답한다. 
- 주기적으로 웹 어플리케이션 취약점 진단을 실시한다. 

## 사용자 환경 
- 악의적인 사이트로 유도되어도 접속되지 않도록 화이트 리스트 방식의 접근 제한을 실시한다. 

# 참고
- 공격 기본개념: https://portswigger.net/blog/practical-web-cache-poisoning
- CVE 리스트: https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=web+cache+poisoning
- XFH 헤더: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-Host
