---
layout: post
title: "Burp Academy-Path traversal 관련 취약점: File path traversal, simple case"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Path traversal]
toc: true
last_modified_at: 2024-12-25 09:33:00 +0900
---

# 개요
- 문제 주소: https://portswigger.net/web-security/file-path-traversal/lab-simple
- 취약점 설명페이지: https://portswigger.net/web-security/file-path-traversal
- 난이도: APPRENTICE (쉬움)


# 문제 개요
- 이 랩은 상품의 이미지를 표시하는 곳에 Path traversal 취약점이 있다. 
- 랩을 풀려면 /etc/passwd 파일의 내용을 알아내라. 

```
This lab contains a path traversal vulnerability in the display of product images.

To solve the lab, retrieve the contents of the /etc/passwd file.
```

# 풀이
1. 랩에 접속해서 사이트를 살펴본다. 

![](/images/burp-academy-path-traversal-1-1.png)

그러면 위와 같이 상품의 이미지를 "/resources/images/rating2.png", "/image?filename=33.jpg" 경로에서 가져오는 것을 알 수 있다. 

2. "/image?filename=33.jpg" 이 공격가능해보인다. fileanme 파라메터에 경로를 입력하면 어떻게 될까? 

3. "/image?filename=/etc/passwd" 로 접근해보니 그런 파일은 없다고 한다. 

![](/images/burp-academy-path-traversal-1-2.png)


4. 이번에는 페이로드를 "/image?filename=../../../../../../../../etc/passwd"로 해서 접근해본다. 그러면 `/etc/passwd` 파일의 내용이 회신된 것을 알 수 있다. 


![](/images/burp-academy-path-traversal-1-3.png)


5. 랩이 풀렸다. 


![](/images/burp-academy-path-traversal-1-success.png)
