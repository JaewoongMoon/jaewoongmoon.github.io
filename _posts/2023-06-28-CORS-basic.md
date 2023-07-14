---
layout: post
title: "CORS 기본 정리"
categories: [웹보안, CORS]
tags: [웹보안, CORS]
toc: true
last_modified_at: 2023-06-28 17:02:00 +0900
---


# 개요/배경
- CORS는 Cross-Origin Resource Sharing의 약자이다. 
- Javascript 활용이 활발해지면서 [동일 출처 정책(SOP)]({% post_url 2023-06-28-동일출처정책-SOP %})의 제한을 넘어서 사이트 간에 데이터를 교환(크로스 도메인)하려는 요구가 강해졌다. 
- Javascript는 동일 출처 정책에 제한받기 때문에 크로스 사이트간 데이터교환(Ajax요청 등)이 불가능하다. (정확히는 요청은 가능해도 응답에 접근못한다.)
- 이 제한을 극복하고자 제안된 것이 CORS 이다. 
- 조건이 갖추어진 환경(헤더에 접근 허용 도메인 지정 등) 하에서 데이터 교환을 할 수 있다. 
- 중요한 것은 **리소스를 가진 서버측에서 권한을 설정** 해준다는 점이다. 
- 클라이언트 측 요청은 여러 구현 방법이 있지만 주로 XMLHttpRequest를 사용한다. 

XMLHttpRequest의 코드는 다음과 같다. 

```javascript
  var req = new XMLHttpRequest();
  req.open('GET', 'http://a-url');
  req.onreadystatechange = function() {
    if (req.readyState == 4 && req.status == 200) {
      alert(req.responseText);
    }
  };
req.send(null);
```

- [CORS는 JSONP 의 대체수단으로 쓰일 수 있다.][1]
- [크로스 도메인 에러가 발생하면 브라우저에서 다음과 같은 메세지를 출력한다.][2]

```
XMLHttpRequest cannot load [FQDN]. 
No 'Access-Control-Allow-Origin' header is present on the requested resource.
Origin '[FQDN]' is therefore not allowed access.
```

- CORS는 결국 SOP의 제한을 풀어주는 역할을 하므로 XSS공격을 포함한 잠재적인 공격 위험도 늘어나게 된다. 
- 따라서 CORS를 사용할 때에는 설정에 문제가 없는지(취약점이 없는지) 잘 체크해야 한다. 

# CORS 역사
- 2004년에 Matt Oshry, Brad Porter, Michael Bodell 라는 사람에 의해 VoiceXML이라는 기술의 일부분으로써 크로스오리진 요청 스펙이 제안되었다. 
- 후에 2006년에 보다 일반적인 기술로써 W3C에 초안이 제안되었고, 2009년에 이 초안의 이름이 Cross-Origin Resource Sharing로 바뀐다. 
- 2014년 1월에 W3C의 추천기술로 채택되었다. 
- 비교적 역사가 짧기 때문에 오래된 브라우저는 CORS에 대응하지 않을 수 있다. 


# CORS 요청 헤더
- 클라이언트(브라우저)측에서 CORS요청을 보낼 때 HTTP요청에 추가하는 헤더이다. 
- `Access-Control-Request-Method`, `Access-Control-Request-Headers`, `Origin` 세 헤더가 사용된다.

# CORS 응답 헤더 
다음 헤더들은 **서버측(응답측)에서 지정하는 HTTP헤더**이다. 다음은 CORS헤더를 포함한 HTTP응답 예이다. 

```http
HTTP/1.1 200 OK
Content-Length: 0
Connection: keep-alive
Access-Control-Allow-Origin: https://foo.bar.org
Access-Control-Allow-Methods: POST, GET, OPTIONS, DELETE
Access-Control-Allow-Headers: Content-Type, x-requested-with
Access-Control-Max-Age: 86400

```

## Access-Control-Allow-Origin 
서버 입장에서 자신의 사이트의 컨텐츠에 접근을 허용할 클라이언트 도메인을 지정할 수 있다. `*` 로 지정할 경우 모든 도메인으로 부터의 접근을 허용한다. 보안상 위험하다. 

## Access-Control-Allow-Methods 
클라이언트측에서 사용가능한 HTTP 요청 메서드를 지정한다. POST, GET 등이다. 

## Access-Control-Max-Age 
권한 확인을 위한 Preflight 요청이 캐시될 시간(초) 지정한다. 

## Access-Control-Allow-Headers
허용할 클라이언트 측 HTTP 요청 헤더 값을 지정한다.  예를들어 `x-requested-with` 라고 지정할 경우 Ajax 요청만 허용한다. 

## Access-Control-Allow-Credentials 
가능한 값은 true이다. 필요없으면 이 헤더 자체를 생략하면 된다. 클라이언트측의 인증정보(세션 쿠키등)를 포함한 요청에 대해 응답을 허용할지를 지정한다. 이 헤더는 클라이언트측의 다음 코드와 쌍으로 동작한다. 자바스크립트의 `req.withCredentials = true;`가 있어서 CORS요청시 인증정보가 함께 서버로 전송된다. 그리고 서버측에서 `Access-Control-Allow-Credentials: true `헤더로 허용을 해주어야 클라이언트측에서 서버의 리소스에 접근할 수 있다. 

```javascript
var req = new XMLHttpRequest();
req.open('GET', 'https://xxx.com');
req.withCredentials = true;
```


# CORS 동작과정 예
어떤 서버(서버A)가 다른 서버(서버B)에 리소스를 요청할 때를 생각해본다. 

서버A는 다음과 같은 요청을 보낸다. 서버A의 도메인은 foo.example이다. `Origin`헤더에 이 값이 지정되어 있다. 

```http
GET /resources/public-data/ HTTP/1.1
Host: bar.other
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:71.0) Gecko/20100101 Firefox/71.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-us,en;q=0.5
Accept-Encoding: gzip,deflate
Connection: keep-alive
Origin: https://foo.example

```

리소스를 가지고 있는 서버B는 HTTP응답에 다음과 같이 CORS 헤더를 추가해야 한다. 클라이언트측의 브라우저는 이를 보고 허용되었구나라고 판단하여 리소스에 접근시켜준다. 

```http
Access-Control-Allow-Origin: https://foo.example
```

# 프리플라이트(Preflight) 요청 
- CORS 가 동작할 때 사실은 프리플라이트 요청이라는 것이 먼저 날라간다. 
- 날기전에(Preflight) 날아도 되는지 확인하는 과정이라고 이해하면 될 것 같다. 
- 날아도 된다는 확인이 되었을 때 실제 크로스 오리진 요청이 보내진다. 
- 프리플라이트 요청은 HTTP의 OPTIONS 메서드를 사용해서 보내진다. 
- `Access-Control-Request-Method`, `Access-Control-Request-Headers`, `Origin` 세 헤더가 사용된다. 각각 어떤 HTTP 메서드를 사용하고 싶은지, 어떤 요청헤더를 사용하고 싶은지 어떤 오리진에서 보내는지를 나타낸다. 
- [다음과 같다.][4]

```
OPTIONS /resource/foo
Access-Control-Request-Method: DELETE
Access-Control-Request-Headers: origin, x-requested-with
Origin: https://foo.bar.org
```

서버가 CORS에 대응하고 있다면 응답을 해주어야 한다. 

```
HTTP/1.1 204 No Content
Connection: keep-alive
Access-Control-Allow-Origin: https://foo.bar.org
Access-Control-Allow-Methods: POST, GET, OPTIONS, DELETE
Access-Control-Max-Age: 86400
```

## 프리플라이트 요청이 필요한(존재하는) 이유
- [여기](https://stackoverflow.com/questions/15381105/what-is-the-motivation-behind-the-introduction-of-preflight-cors-requests#:~:text=Preflight%20requests%20were%20introduced%20so,to%20the%20Same%20Origin%20Policy).)에 잘 설명되어 있다. 
- 간단히 요약하면 서버가 CORS에 대응하고 있는지를 모르는 상태에서 요청을 보내고 (예를들어 DELETE요청과 같은 위험한 요청을 보내고), 그 요청이 서버에서 처리되어 버리면 위험하기 때문에 미리 서버가 CORS에 대응하고 있는지 체크한다는 흐름인 것 같다. CORS에 대응하고 있지 않다면 브라우저는 이후의 요청 (실제 요청)을 보내지 않는다. (마치 CSRF공격을 막는 메커니즘같다.)
- 이런 배경때문에 프리플라이트 요청은 CSRF대책으로도 활용된다. 

프리플라이트요청이 CSRF 대책으로 활용되는 것에 대한 정보는 이하의 링크에서 확인할 수 있다. 
- https://stackoverflow.com/questions/41148282/why-doesnt-pre-flight-cors-block-csrf-attacks
- https://portswigger.net/daily-swig/chrome-to-bolster-csrf-protections-with-cors-preflight-checks-on-private-network-requests : 크롬에서도 내부 네트워크 서버에 대한 CSRF대책으로 프리플라이트 요청을 활용하는 것 같다. 
- https://www.apollographql.com/docs/router/configuration/csrf/ : Node.js의 GraphQL 서버인 apollo에서도 
- 


# 프리플라이트 요청이 필요없는 경우
- 간단한 요청(simple request)라고 불리는 요청인 경우에는 프리플라이트 요청이 발생하지 않는다. 
- 원래부터 존재했던 HTML폼도 크로스 오리진 요청이 가능하기 때문에, HTML 폼을 사용해서 전송되는 정도(간단한 요청)면 리스크가 크게 증가하지 않는다고 판단한 것 같다. 

## 간단한 요청의 조건 
간단한 요청의 조건은 다음 세 가지를 모두 만족하는 요청이다. 

1. 다음 중 하나의 메서드 (DELETE는 안된다.)
- GET
- HEAD
- POST

2. 유저 에이전트가 자동으로 설정 한 헤더외에 수동으로 설정된 헤더는 다음의 헤더들만 가능
- Accept
- Accept-Language
- Content-Language
- Content-Type 

3. Content-Type 헤더는 다음의 값들만 가능 (`application/json`은 안 된다.)
- application/x-www-form-urlencoded
- multipart/form-data
- text/plain

# 참고 
- https://developer.mozilla.org/ko/docs/Web/HTTP/CORS


[1] https://en.wikipedia.org/wiki/Cross-origin_resource_sharing
[2] http://ooz.co.kr/232
[3] https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials
[4] https://developer.mozilla.org/en-US/docs/Glossary/Preflight_request