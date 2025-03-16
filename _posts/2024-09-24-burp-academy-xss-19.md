---
layout: post
title: "Burp Academy-XSS 취약점: Reflected XSS with some SVG markup allowed"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XSS취약점]
toc: true
last_modified_at: 2024-09-24 21:55:00 +0900
---

# 개요
- 취약점 설명 주소: https://portswigger.net/web-security/cross-site-scripting/contexts
- 문제 주소: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-some-svg-markup-allowed
- 난이도: PRACTITIONER (보통)


# 랩 개요 
- 이 랩에는 반사형 XSS취약점이 있다. 이 사이트는 일반적인 태그는 블록킹하고 있지만 몇몇 SVG 태그와 이벤트는 미처 블록킹하지 못하고 있다. 
- 랩을 풀려면 XSS공격을 수행해서 alert함수를 실행시킨다. 

```
This lab has a simple reflected XSS vulnerability. The site is blocking common tags but misses some SVG tags and events.

To solve the lab, perform a cross-site scripting attack that calls the alert() function.
```

# 도전 
1. 일단 사용가능한 tag를 찾는다. [XSS 치트시트](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) 페이지에서, "Copy tags to clipboard" 를 선택해서 Intruder의 Payloads에 등록하고 공격을 시도해본다. 

![](/images/burp-academy-xss-19-1.png)

2. 결과는 다음과 같다. `animatetransform`, `image`, `svg`, `title` 네 개의 태그는 사용가능한 것을 알 수 있다. 

![](/images/burp-academy-xss-19-2.png)


3. 이어서 사용가능한 이벤트를 체크해본다. 일단 태그는 svg로 고정한다. Intruder에서 검색 키워드를 `<svg%20§§=1>`로 변경한다. Payloads 탭에서 Payload를 일단 클리어(Clear)한 뒤에 [XSS 치트시트](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) 에서 "Copy events to clipboard" 를 선택한 후 Payload에 붙여넣기 한다. 그 후 Attack버튼을 눌러서 공격한다. 

![](/images/burp-academy-xss-19-3.png)

4. 결과는 다음과 같다. `onbegin` 이벤트는 사용 가능한 것을 알 수 있다. 

![](/images/burp-academy-xss-19-4.png)

5. 검색창에서 페이로드를 시험해본다. `<svg onbegin=alert(1);>`은 alert창이 안 뜨는 것을 알 수 있다. `<svg><animatetransform onbegin=alert(1);>` 과 같이 svg 태그와 animatetransform 태그를 함께 사용할 때만 alert창이 뜬다. 

6. alert창이 뜨고 나면 문제가 풀렸다는 메세지가 표시된다. 

![](/images/burp-academy-xss-19-success.png)

# 보충설명

Mozilla 에서 설명하는 [스펙](https://developer.mozilla.org/en-US/docs/Web/SVG/Element/animateTransform)을 보면 `animatetransform` 태그는 `svg` 태그의 하위에 위치하여 svg로 표현한 그래픽에 애니메이션 처리를 추가해주는 역할인 것으로 보인다. 즉, `svg`태그와 함께 세트로 있어야 동작한다. 그리고 `onbegin` 이벤트도 [스펙](https://developer.mozilla.org/en-US/docs/Web/API/SVGAnimationElement/beginEvent_event) 페이지를 보면, svg 애니메이션에서 사용가능한 이벤트로, 엘레먼트의 로컬 타임라인이 애니메이션을 플레이할 준비가 되었을 때 호출된다고 한다. 즉 `animatetransform` 태그에서 사용할 수 있는 이벤트인 것이다. 