---
layout: post
title: "Burp Academy-NoSQLi 관련 취약점: Detecting NoSQL injection"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, SQLi, NoSQL, NoSQL injecition]
toc: true
last_modified_at: 2023-10-02 09:50:00 +0900
---

# 개요
- 새로 추가된 NoSQL인젝션 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-detection
- 취약점 설명페이지: https://portswigger.net/web-security/nosql-injection
- 난이도: APPRENTICE (쉬움)

# NoSQL 인젝션 메모
- NoSQL인젝션은 크게 syntax injection과 operator injection의 두 가지 타입이 있다. 
- syntax injection은 기존의 SQL인젝션과 비슷하다. SQL에서 쓰이는 연산자 등을 사용할 수 있다. 
- operator injection은 NoSQL(특히 MongoDB)에서 사용되는 `$where, $ne, $in, $regex`등을 사용한 인젝션 기법이다. 

# 문제 설명
- 랩 서버는 MongoDB를 사용하고 있고 NoSQL인젝션 취약점이 있다. 
- NoSQL 인젝션을 사용해서 아직 공개되지 않은 상품을 페이지 표시하면 문제가 풀린다. 

```
The product category filter for this lab is powered by a MongoDB NoSQL database. It is vulnerable to NoSQL injection.

To solve the lab, perform a NoSQL injection attack that causes the application to display unreleased products.
```

# 관찰
1. 문제 서버에 접속하면 쇼핑몰 사이트가 보인다. 이 사이트에는 카테고리별로 상품을 볼 수 있는 기능이 있다. 

![문제서버확인](/images/burp-academy-nosqli-1-1.png)

2. 카테고리를 클릭시 다음과 같은 요청이 전송된다. 

```http
GET /filter?category=Accessories HTTP/2
Host: 0ad600b303e6361b81fb358600270035.web-security-academy.net
Cookie: session=BBXq5Fj5Y6eHsyAc0GUceVtaEtagqgu7
Sec-Ch-Ua: "Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0ad600b303e6361b81fb358600270035.web-security-academy.net/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7


```

# SQL 인젝션 될지 테스트
1. 파라메터에 작은따옴표(')를 붙여서 보내본다. 요청 경로가 `/filter?category=Accessories%27`가 된다.

그러면 다음과 같이 문법 에러 화면이 나타난다. 이는 작은 따옴표가 서버측에서 파라메터가 아닌 SQL문으로 사용된 것을 의미한다. 

![에러화면](/images/burp-academy-nosqli-1-2.png)

2. 이번엔 작은따옴표 앞에 이스케이프를 의미하는 역슬래시(\)를 붙여서 보내본다. 경로는 `filter?category=Accessories\%27`가 된다. 

그러면 이번에는 에러없이 정상적으로 처리된 것을 볼 수 있다. 이 것으로 SQL 인젝션이 가능하다는 것을 확인했다.  

![정상처리화면](/images/burp-academy-nosqli-1-3.png)

# True/False 컨디션에 따라 동작이 달라지는지 테스트
컨디션에 따라 서버 동작이 달라지는지 테스트하려면 True 컨디션 요청과 False 컨디션 요청을 각각 보내보면 된다. 

True는 `' && 1 && 'x`을, False는 `' && 0 && 'x`를 사용한다. And조건(&&)을 사용하기 때문에, True/False에 따라 서버 동작이 달라지는 것을 확인하는데 유용하다. 

이를 URL형태로 표현하면 True는 `https://insecure-website.com/product/lookup?category=fizzy'+%26%26+1+%26%26+'x`가 , False는 `https://insecure-website.com/product/lookup?category=fizzy'+%26%26+0+%26%26+'x` 가 된다. 

1. True조건을 테스트해본다. `https://0ad600b303e6361b81fb358600270035.web-security-academy.net/filter?category=Accessories%27+%26%26+1+%26%26+%27x` 로 요청을 보내면 다음과 같이 화면에 상품이 표시된다. 

![True조건 테스트 결과](/images/burp-academy-nosqli-1-4.png)

2. False조건을 테스트해본다. 상품이 표시되지 않는다. 이 테스트 결과에 따라, True/False 컨디션에 따라 동작이 달라지는 것을 확인했다.  

![False조건 테스트 결과](/images/burp-academy-nosqli-1-5.png)

# 기존의 컨디션을 덮어쓰기
서버가 True/False 컨디션에 따라 동작을 달리하는 것을 확인했다. 그러면 이제 카테고리별로 상품을 표시하는 요청에 OR 1=1조건으로 컨디션을 덮어써보자. 그러면 모든 카테고리(아직 릴리즈되지 않은 상품을 포함해서)의 상품이 표시될 수도 있다. 

이를 위해 `'||1||'` 파라메터를 사용한다. 이 파라메터로 서버에 요청을 보내면 문제가 풀렸다는 메세지가 출력된다. 아직 아직 릴리즈되지 않은 상품을 표시하는데 성공한 것이다. 

![문제풀이 성공](/images/burp-academy-nosqli-1-success.png)

참고로, MongoDB에서는 SQL에서 Null캐릭터 다음의 쿼리는 처리하지 않는다고 한다. 기존의 SQL인젝션에서 주석과 비슷한 효과가 나타나는 것이다. Null 캐릭터를 URL로 표현하면 `%00` 다. 따라서 위의 문제는 `'%00` 파라메터를 사용해도 풀 수 있다. (`this.category == 'fizzy'\u0000' && this.released == 1` 와 같이 released 조건을 처리하는 쿼리부분을 무시하게 만듦으로서 모든 상품이 표시되게 하는 원리이다.)