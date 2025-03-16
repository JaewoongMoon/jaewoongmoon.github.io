---
layout: post
title: "Burp Academy-XSS 취약점: Stored XSS into anchor href attribute with double quotes HTML-encoded"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XSS취약점]
toc: true
last_modified_at: 2025-02-28 05:55:00 +0900
---

# 개요
- HTML 태그의 속성에서 발생하는 XSS 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-href-attribute-double-quotes-html-encoded
- 난이도: APPRENTICE (쉬움)

# 문제
- 이 사이트의 블로그의 댓글 기능에 Stored XSS취약점이 존재한다. 
- 랩을 풀려면 댓글의 작성자를 클릭하면 alert함수가 실행되도록 하면 된다. 

```
This lab contains a stored cross-site scripting vulnerability in the comment functionality. To solve this lab, submit a comment that calls the alert function when the comment author name is clicked.
```

# 풀이 
1. 랩을 관찰한다. 댓글 쓰는 폼이 있다. 

![](/images/burp-academy-xss-8-1.png)

2. 입력란에 XSS 페이로드를 입력해본다. 그러면 HTML 이스케이프 처리가 잘 되고 있는 것을 알 수 있다. 

![](/images/burp-academy-xss-8-2.png)

3. 그 중에, 작성자의 웹사이트로 입력한 값이 앵커 태그의 href 속성으로 출력되는 것을 알 수 있다. 

![](/images/burp-academy-xss-8-3.png)

4. 웹 사이트에 `javascript:alert(1)`을 입력한다. 

![](/images/burp-academy-xss-8-5.png)

5. 입력한 후의 화면이다. 작성자 이름을 클릭한다. 

![](/images/burp-academy-xss-8-6.png)

6. alert창이 뜨는 걸 확인했다. 

![](/images/burp-academy-xss-8-7.png)

7. 그런데 alert창이 뜨는데도 풀렸다는 메세지가 안 나온다. 

한번 더 댓글을 남겨보자. 이번에는 제출하자 랩이 풀렸다. 

![](/images/burp-academy-xss-8-8.png)