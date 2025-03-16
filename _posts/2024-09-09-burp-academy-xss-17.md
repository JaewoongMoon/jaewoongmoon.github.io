---
layout: post
title: "Burp Academy-XSS 취약점: Exploiting cross-site scripting to capture passwords"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XSS취약점]
toc: true
last_modified_at: 2024-09-02 21:55:00 +0900
---

# 개요
- 취약점 설명 주소: https://portswigger.net/web-security/cross-site-scripting/contexts
- 문제 주소: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-most-tags-and-attributes-blocked
- 난이도: PRACTITIONER (보통)


# 랩설명
- 랩 사이트에는 검색 기능에 반사형 XSS 취약점이 있다. 
- 그러나 WAF를 사용하고 있으므로 일반적인 XSS공격 벡터를 방어하고 있다. 
- 랩을 풀려면 XSS공격을 수행해서 WAF를 우회하여 print()함수를 호출하라. 
- 참고: 해결책에는 사용자 상호 작용이 필요하지 않아야 한다. 자신의 브라우저에서 print()를 수동으로 호출하는 것으로는 랩을 풀 수 없다.

```
This lab contains a reflected XSS vulnerability in the search functionality but uses a web application firewall (WAF) to protect against common XSS vectors.

To solve the lab, perform a cross-site scripting attack that bypasses the WAF and calls the print() function.

Note
Your solution must not require any user interaction. Manually causing print() to be called in your own browser will not solve the lab.
```


# 도전
1. 일단 살펴본다. 블로그 검색기능에서 XSS 페이로드 `<script>alert(1)</script>`를 입력해보면 다음과 같이 tag는 허용되지 않는다고 표시된다. WAF에 의한 XSS방어 기능이 동작하고 있다. 

![](/images/burp-academy-xss-17-1.png)

2. WAF에서 미처 방어하지 못한 페이로드가 있을 지도 모른다. Burp Intruder를 사용해서 여러 개의 페이로드를 테스트해보자. 

3. 블로그 검색요청을 Intruder로 보낸다. 

4. Positions 탭에서 변경될 부분인 search파라메터의 값을 태그를 정의하는 괄호 `<>`로 감싼다. 그리고 값 부분을 선택한 후, 오른쪽의 Add버튼을 누른다. 다음과 같다. 

![](/images/burp-academy-xss-17-3.png)

5. [XSS Cheatsheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)에서 "Copy tags to clipboard"를 클릭한다. 

6. Burp Intruder의 Payloads 탭에서 Paste 를 눌러서 페이로드 리스트에 추가한다. 그리고 "Start Attack"버튼을 클릭한다. 

7. 결과를 확인한다. 그러면 `body` 태그와 커스텀 태그는 200응답인 것을 알 수 있다. `body`태그를 사용해서 페이로드를 만들어간다. 

![](/images/burp-academy-xss-17-4.png)

8. 이제 WAF에 블록되지 않는 사용가능한 이벤트를 찾아야 한다. Positions 탭에서 serach 파라메터의 값을 `<body%20=1>`로 만든다. 그리고 = 앞에 커서를 위치시킨 후 Add 버튼을 두번누른다. 그러면 다음과 같이 파라메터의 값이 `<body%20§§=1>`로 바뀐다. Intuder가 공격을 시작하면 `§§`부분이 테스트할 페이로드로 변경될 것이다. 

![](/images/burp-academy-xss-17-5.png)

9. 다시 [XSS Cheatsheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)에서 "copy events to clipboard"를 클릭한다. 

10. Burp Intruder의 Payloads 탭에서 "Clear" 버튼을 눌러서 이전의 페이로드를 삭제한다. "Paste"버튼을 눌러서 현재의 페이로드 리스트를 추가한다. 그리고 "Start Attack"버튼을 클릭한다. 

11. 결과를 확인한다. 몇 개의 이벤트는 사용할 수 있는 것을 알 수 있다. 이 중에서 `onresize`이벤트를 활용한다. 이 이벤트는 브라우저의 창의 크기가 변경되면 발동한다. 

![](/images/burp-academy-xss-17-6.png)

12. 다음 페이로드를 사용한다. 이 페이로드를 victim의 브라우저에서 실행하도록 만들면 어떻게 될까? iframe에서 크기를 바꾸므로 iframe 내부에 표시하는 랩의 화면에서는 `onresize` 이벤트가 발생한다. 그 결과 페이로드에 지정한 print()함수가 실행된다. WAF를 우회해서 victim의 브라우저에서 실행되는 코드를 전송한 것이다! 

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>
```

13. 위의 페이로드에서 `YOUR-LAB-ID`를 현재 랩의 ID로 변경한 후, exploit 서버에 저장한 후에 "Deliver exploit to victim"를 클릭한다. 

14. 그러면 문제가 풀렸다는 메세지가 표시된다. 

![](/images/burp-academy-xss-17-7.png)