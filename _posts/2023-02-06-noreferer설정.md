---
layout: post
title: "Referer 헤더를 보내고 싶지 않을 때"
categories: [웹 방어 기술, HTTP 헤더]
tags: [웹 방어 기술, HTTP 헤더]
toc: true
---

# 개요
- HTML 페이지에 타 사이트의 리소스(스타일시트, 자바스크립트, 이미지 등)를 포함시키는 경우가 있다. 
- 이 HTML 페이지를 로딩하면 브라우저는 타 사이트의 리소스를 요청하게 되는데 이 때 Referer헤더에 내 사이트의 도메인 정보가 전달된다.  
- 예를 들면 다음과 같은 식이다. 
```
Referer: https://developer.mozilla.org/en-US/docs/Web/JavaScript
Referer: https://example.com/page?q=123
Referer: https://example.com/
```
- 리소스를 제공하는 사이트측에서는 Referer 헤더 정보를 보고 어느 사이트에서 내 리소스를 요청했구나라고 파악할 수 있다. 
- 그런데 비밀리에 개발중인 사이트거나 하는 경우에는 도메인 정보를 노출시키고 싶지 않을 수도 있다. 
- 이럴 때 사용할 수 있는 방법을 조사해보았다. 

# 조사 결과 
- 이럴 때 사용할 수 있는 방법중에 가장 간단한 것은 HTML 페이지의 태그에 속성(property)을 설정하는 방법이다. 
- `rel="noreferrer"`와 `referrerpolicy="no-referrer"` 를 설정할 수 있다. 
- `rel="noreferrer"`는 조금 제약사항이 있어서 `link`나 `script`태그에는 사용할 수 없다. `<a>`,`<area>`,`<form>`태그에는 사용할 수 있다. 
- `link`나 `script`태그에는 `referrerpolicy="no-referrer"` 를 설정하면 된다. 
- 하나 유의해야 할 점은 이 속성을 브라우저가 이해하고 대응해주는가 여부이다. 물론 최신브라우저라면 대응하고 있다. 
- 아래 참고 링크에 브라우저별 호환성(Browser compatibility)가 상세하게 나와있으므로 참고하면 된다. 

# 참고 링크
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer
- https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes/rel/noreferrer
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
