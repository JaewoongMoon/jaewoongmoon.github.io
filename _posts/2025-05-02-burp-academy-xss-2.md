---
layout: post
title: "Burp Academy-XSS 취약점: Reflected XSS into HTML context with nothing encoded"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XSS취약점]
toc: true
last_modified_at: 2025-04-28 21:55:00 +0900
---

# 개요
- 저장형 타입의 XSS 취약점 랩이다.
- 문제 주소: https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded
- 취약점 설명: https://portswigger.net/web-security/cross-site-scripting/stored
- 난이도: APPRENTICE (쉬움)


# 랩 개요
- 이 랩은 댓글 저장기능에 저장형 XSS취약점이 있다. 
- 랩을 풀려면 블로그 포스트를 조회했을 때 alert함수를 실행시키는 댓글을 저장하라. 

```
This lab contains a stored cross-site scripting vulnerability in the comment functionality.

To solve this lab, submit a comment that calls the alert function when the blog post is viewed.
```

# 도전
1. 랩 서버에서 블로그 글 하나를 선택해서 상세 화면으로 이동한다. 다음과 같이 Comment란에 스크립트 `<script>alert(document.cookie)</script>`를 적고 Post Comment 버튼을 눌러서 저장한다. 

![](/images/burp-academy-xss-2-1.png)

2. 저장후에 다시 해당 페이지를 열면 alert창이 뜨는 것을 확인할 수 있다. 랩이 풀렸다. 

![](/images/burp-academy-xss-2-success.png)