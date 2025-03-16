---
layout: post
title: "COOP(Cross-Origin-Opener-Policy) 개요"
categories: [Web 개발, 웹보안]
tags: [Web개발,웹보안, COOP]
toc: true
last_modified_at: 2025-01-08 09:33:00 +0900
---

# 개요
CORS 이외에 웹 보안을 강화하는 메커니즘으로 COOP(Cross-Origin-Opener-Policy) 이 있다. COOP에 대해서 정리해둔다. 


# COOP(Cross-Origin-Opener-Policy) 이란?
- HTTP 응답에 설정하는 헤더로, 브라우저가 다른 출처의 창이나 탭을 열 수 있는지 여부를 제어하는 ​​보안 정책이다. 
- 웹 브라우저가 어떤 사이트를 열 때 이 사이트의 응답에 COOP 헤더가 있으면 이 헤더의 값에 따라 동작을 수행한다. 
- COOP은 XS-Leak 공격에 대한 방어책이 된다. 

MDN에서는 다음과 같이 설명하고 있다. 

```
HTTP COOP(Cross-Origin-Opener-Policy) 응답 헤더를 사용하면 웹사이트에서 Window.open()을 사용하거나 새 페이지로 이동하여 열린 새 최상위 문서를 동일한 브라우징 컨텍스트 그룹(BCG)에서 열 것인지 아니면 새 탐색 컨텍스트 그룹에서 열 것인지 제어할 수 있습니다.

The HTTP Cross-Origin-Opener-Policy (COOP) response header allows a website to control whether a new top-level document, opened using Window.open() or by navigating to a new page, is opened in the same browsing context group (BCG) or in a new browsing context group.

새 BCG에서 열면 새 문서와 오프너 간의 모든 참조가 끊어지고 새 문서는 오프너에서 프로세스 격리될 수 있습니다. 이렇게 하면 잠재적 공격자가 Window.open()으로 문서를 열고 반환된 값을 사용하여 글로벌 객체에 액세스할 수 없으므로 XS-Leaks라고 하는 일련의 교차 출처 공격을 방지할 수 있습니다.

When opened in a new BCG, any references between the new document and its opener are severed, and the new document may be process-isolated from its opener. This ensures that potential attackers can't open your documents with Window.open() and then use the returned value to access its global object, and thereby prevents a set of cross-origin attacks referred to as XS-Leaks.
```

# 문법, 지시자 (Syntax, Directives)

헤더는 다음과 같이 생겼다. 

```http 
Cross-Origin-Opener-Policy: unsafe-none | same-origin-allow-popups | same-origin
```

## unsafe-none
기본값이다. `unsafe-none` 이면 크로스 도메인에 해당 문서가 공유된다. 따라서 안전하지 않다. 


## same-origin
COOP헤더에 이 값이 설정된 웹 문서는 동일 출처 문서만 포함하는 BCG에 로드하는 것을 허용한다. 이는 BCG에 대한 교차 출처 격리(crossOriginIsolated)를 제공하는 데 사용된다. 

출처가 동일한 문서는 두 문서가 모두 동일한 출처이고 동일한 출처 지시문이 있는 경우에만 동일한 BCG에서 열린다. 


# POC 
COOP이 설정된 사이트를 열어보면 `window.opener`의 값이 `null`이 된다. 이는 사이트를 open하는 쪽에서 open되는쪽으로의 참조를 모두 잃어버렸음을 의미한다. 

# 브라우저 대응 현황

2025년 1월 기준, COOP은 Android WebView를 제외한 모든 메이저 브라우저에서 지원한다. 

![](/images/coop-browser-compatibility-2025-01.png)

# 결론 
- 중요한 페이지에는 COOP헤더를 설정하자. 
- 특히 OAuth 인증서버와 같은 곳(OAuth 관련 토큰이 왔다갔다 하는 곳)에서는 설정해두는게 좋겠다. 

# 추가

cross-origin isolation 을 실행하려면 다음과 같다. 한다. 

1. Set `Cross-Origin-Opener-Policy: same-origin` for the main document. 
2. Make sure cross-origin resource use `Cross-Origin-Resource-Policy: cross-origin` or CORS. 
   - (주의: CDN과 같은 리소스 제공자측에서는 `Cross-Origin-Resource-Policy: cross-origin`헤더를 설정해야 한다.)
3. 


# 참고
- https://velog.io/@hoho3419/COOP-%EC%99%80-CORS
- https://www.hahwul.com/cullinan/coop/
- https://www.hahwul.com/2021/07/31/protecting-more-with-site-isolation-from-google/
- COOP 사양에 대한 상세한 정보: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy
- https://asnokaze.hatenablog.com/entry/2019/05/08/021811
- COOP + COEP = cross-origin isolated: https://web.dev/articles/coop-coep
- https://web.dev/articles/why-coop-coep