---
layout: post
title: "Burp Academy-API Testing 관련 취약점: Exploiting an API endpoint using documentation"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, API Testing]
toc: true
last_modified_at: 2025-01-06 09:33:00 +0900
---

# 개요
- 문제 주소: https://portswigger.net/web-security/api-testing/lab-exploiting-api-endpoint-using-documentation
- 취약점 설명페이지: https://portswigger.net/web-security/api-testing
- 난이도: APPRENTICE (쉬움)


# 문제 개요
- 랩을 풀려면 노출되어 있는 API 문서를 찾고 carlos 유저를 삭제하라. 
- wiener:peter 크레덴셜을 사용해서 로그인할 수 있다. 

```
To solve the lab, find the exposed API documentation and delete carlos. You can log in to your own account using the following credentials: wiener:peter.

```

# 풀이
1. 취약점 설명페이지에서 설명되어 있는 알려진 API문서 엔드포인트는 다음과 같다. 이 엔드포인트로 하나씩 접속해서 응답이 있는지 확인한다. 

- `/api`
- `/swagger/index.html`
- `/openapi.json`

2. `/api` 엔드포인트로 접근하자 다음과 같이 API 목록을 보여준다. 

![](/images/burp-academy-api-testing-1-1.png)

3. DELETE 를 클릭해보면 다음과 같이 유저 삭제를 실행할 수 있는 팝업이 뜬다. carlos 를 입력하고 Send Request 버튼을 클릭한다. 

![](/images/burp-academy-api-testing-1-2.png)

4. 다음과 같은 HTTP요청이 전송된다. 정상처리되어 200응답이 회신된다. 

![](/images/burp-academy-api-testing-1-3.png)

5. 랩이 풀렸다. 

![](/images/burp-academy-api-testing-1-success.png)