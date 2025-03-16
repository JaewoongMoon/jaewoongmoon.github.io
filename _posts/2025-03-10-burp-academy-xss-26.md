---
layout: post
title: "Burp Academy-XSS 취약점: Reflected XSS with event handlers and href attributes blocked"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XSS취약점]
toc: true
last_modified_at: 2025-03-10 05:55:00 +0900
---

# 개요
- 취약점 설명 주소: https://portswigger.net/web-security/cross-site-scripting/contexts/
- 랩 주소: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-event-handlers-and-href-attributes-blocked
- 난이도: EXPERT (어려움)


# 랩 개요
- 이 랩에는 일부 화이트리스트된 태그가 포함된 반사형 XSS 취약점이 포함되어 있지만 모든 이벤트와 앵커 href속성은 차단된다.
- 랩을 풀려면, 클릭하면 alert 함수를 호출하는 벡터를 주입하는 크로스 사이트 스크립팅 공격을 수행하라. 
- 시뮬레이션된 랩 사용자가 벡터를 클릭하도록 유도하려면 벡터에 "Click"이라는 단어를 사용해야 한다. 예를 들면 다음과 같다: `<a href="">Click me</a>`

```
This lab contains a reflected XSS vulnerability with some whitelisted tags, but all events and anchor href attributes are blocked.

To solve the lab, perform a cross-site scripting attack that injects a vector that, when clicked, calls the alert function.

Note that you need to label your vector with the word "Click" in order to induce the simulated lab user to click your vector. For example:

<a href="">Click me</a>
```


# 도전

1. 일단 XSS 페이로드를 사용가능한지 체크해본다. 

![](/images/burp-academy-xss-26-1.png)

2. "Tag is not allowed" 라는 메세지가 출력되며 태그를 사용할 수 없다는 것을 알게 되었다. 

![](/images/burp-academy-xss-26-2.png)

3. 문제 설명에 화이트리스트된 (사용가능한) 태그가 있다고 했다. 어떤 태그가 사용가능한지 체크해보자. 검색URL(GET /?search=xxx)을 Intruder로 보낸 후, 파라메터를 `<1>`와 같이 한 후 내부를 포지션으로 추가(Add버튼)한다. [치트시트](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) 에서, "Copy tags to clipboard"를 클릭한 후, Paste를 클릭해서 붙여넣기 한 후, Start Attack을 클릭한다. 

![](/images/burp-academy-xss-26-3.png)

4. 결과는 다음과 같다. a, animate, image, svg, title 5개의 태그가 사용가능한 것을 알 수 있었다. 

![](/images/burp-academy-xss-26-4.png)


5. 그러면 사용가능한 태그를 사용해서 XSS 페이로드를 만들어서 테스트해본다. 


다음 두 개의 페이로드는 "Tag is not allowed" 라는 응답이 돌아왔다. `href`문자열과 `onclick`이라는 문자열은 사용할 수 없는 것으로 보인다. 

```html
<svg><a xlink:href="javascript:alert(1)"><text x="20" y="20">Click Me</text></a>
<svg onclick=this.alert(1)><text x="30" y="30">Click Me</text></svg>
```

다음 두 개의 페이로드는 사용할 수 있었지만 alert창이 뜨지 않았다. 

```html
<svg @click=this.alert(1)><text x="30" y="30">Click Me</text></svg>
<svg@load=this.alert(1)><text x="30" y="30">Click Me</text></svg>
```


![](/images/burp-academy-xss-26-5.png)


![](/images/burp-academy-xss-26-6.png)

6. 정답에 근접한 것 같은데, 이 이후를 어떻게 진행해야할지 모르겠다. 답을 본다. 

7. 정답은 다음과 같다. 다음 경로로 접근하면 랩이 풀린다고 한다. 

```
https://YOUR-LAB-ID.web-security-academy.net/?search=%3Csvg%3E%3Ca%3E%3Canimate+attributeName%3Dhref+values%3Djavascript%3Aalert(1)+%2F%3E%3Ctext+x%3D20+y%3D20%3EClick%20me%3C%2Ftext%3E%3C%2Fa%3E
```

페이로드를 URL디코딩하면 다음과 같이 생겼다. svg태그안에 a태그를 넣고, 그 안에 animate태그를 넣었다. animate태그에는 `attributeName`이라는 속성과 `values`라는 속성이 있다.  `attributeName`에는 태그의 속성인 'href'를, `values`에는 페이로드인 'javascript:alert(1)'를 넣었다. 보통은 'href="javascript:alert(1)' 와 같은 식으로 쓰이는 페이로드를 분리함으로써 감쪽같이 필터를 우회한 것이다! 


```html
<svg><a><animate+attributeName=href+values=javascript:alert(1) /><text+x=20+y=20>Click me</text></a>
```

8. XSS페이로드를 삽입한 HTML응답 페이지는 다음과 같다. Click me 를 클릭하면 alert창이 뜬다. 

![](/images/burp-academy-xss-26-8.png)


![](/images/burp-academy-xss-26-7.png)

9. 랩이 풀렸다. 

![](/images/burp-academy-xss-26-succuess.png)