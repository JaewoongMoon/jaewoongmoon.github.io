---
layout: post
title: "Burp Academy-안전하지 않은 역직렬화(Insecure Deserialization) 관련 취약점: Using application functionality to exploit insecure deserialization"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Insecure Deserialization]
toc: true
last_modified_at: 2024-05-16 21:00:00 +0900
---


# 개요
- 안전하지 않은 역직렬화(Insecure Deserialization) 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-using-application-functionality-to-exploit-insecure-deserialization
- 취약점 설명페이지: https://portswigger.net/web-security/deserialization/exploiting
- 난이도: PRACTITIONER (보통)

# 취약점 개요: 어플리케이션의 기능을 이용하기(Using application functionality)
- 어플리케션의 기능에서도 역직렬화 취약점이 있을 수 있다. 
- 예를들어 유저를 삭제하는 기능에서 , 유저의 프로파일 이미지 삭제기능이 있을 수 있는데, 프로파일 이미지 경로를 외부에서 공격자가 지정할 수 있으면 취약점이 될 수 있다.
- 이런 경우는 공격자가 의도적으로 위험한 메서드(유저의 프로파일 이미지 삭제 메서드)를 호출하는 경우다. 그런데 역직렬화 과정에서 자동으로 호출되는 메서드도 있다. 이 것을 `Magic method`라고 부른다. 

# 문제 개요
- 이 랩은 직렬화 베이스의 세션 관리 메커니즘을 사용하고 있다. 
- 어떤 기능은 직렬화된 오브젝트의 데이터로부터 위험한 메서드를 호출한다. 
- 랩을 풀려면 세션 쿠키 안에 있는 직렬화 오브젝트를 수정해서 Carlos유저의 홈 디렉토리에서 Morale.txt파일을 삭제한다. 
- wiener:peter 크레덴셜로 로그인할 수 있다. 
- 또한 백업 계정(gregg:rosebud)에도 액세스할 수 있다. 

```
This lab uses a serialization-based session mechanism. A certain feature invokes a dangerous method on data provided in a serialized object. To solve the lab, edit the serialized object in the session cookie and use it to delete the morale.txt file from Carlos's home directory.

You can log in to your own account using the following credentials: wiener:peter

You also have access to a backup account: gregg:rosebud
```

# 도전
1. 주어진 크레덴셜로 로그인해보면 이 사이트에는 프로필 이미지 업로드 기능이 있는 것을 알 수 있다. 

![](/images/burp-academy-serial-3-1.png)

2. 프로필 이미지를 등록해본다. 등록시에는 `POST /my-account/avatar` 엔드포인로, `Content-Type: multipart/form-data;` 컨텐트 타입의 요청이 전송된다. 

![](/images/burp-academy-serial-3-2.png)

3. 유저를 삭제해본다. Delete account 버튼을 눌러본다. 


다음과 같은 HTTP 요청이 전송되는 것을 볼 수 있다. 

```http
POST /my-account/delete HTTP/2
Host: 0af10084045a60ca82f0108300a90012.web-security-academy.net
Cookie: session=Tzo0OiJVc2VyIjozOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJibzBhOGZ5dHpkYjFwdjg2eGx6OXFvMWd5OTU4YzdqaSI7czoxMToiYXZhdGFyX2xpbmsiO3M6MTk6InVzZXJzL3dpZW5lci9hdmF0YXIiO30%3d
Content-Length: 0
...

```

4. 세션 쿠키의 값을 Base64 디코딩해서 확인해본다. 

![](/images/burp-academy-serial-3-3.png)


그러면 세션 쿠키의 내용물이 다음과 같은 것을 알 수 있다. `avatar_link`라는 키에 파일 경로 `users/wiener/avatar` 가 값으로 들어가 있는 것을 알 수 있다. 

```
O:4:"User":3:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"bo0a8fytzdb1pv86xlz9qo1gy958c7ji";s:11:"avatar_link";s:19:"users/wiener/avatar";}
```

5. 경로를 수정해본다. `users/carlos/morale.txt` 로 변경한다. 문자열 길이는 19에서 23으로 변경한다. 

```
O:4:"User":3:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"bo0a8fytzdb1pv86xlz9qo1gy958c7ji";s:11:"avatar_link";s:23:"users/carlos/Morale.txt";}
```

6. 수정한 세션토큰 값을 Base64 인코딩해서 보내본다. 그러면 302응답은 돌아오지만 아무 일도 일어나지 않는 것을 알 수 있다. 세션토큰에 지정되어 있는 wiener 계정이 이미 삭제된 상태여서 그런 것으로 보인다. 문제에서 주어진 백업 어카운트로 로그인한 뒤 해당 어카운트의 세션토큰으로 다시 시도해본다. 

![](/images/burp-academy-serial-3-4.png)

7. 그런데 다시 시도해도 302응답은 돌아왔지만 아무 일도 일어나지 않는다. 살짝 답을 본다. 아하..! 경로를 `/home/carlos/morale.txt` 로 해야했다. 

8. 다시 해본다. 풀이에 성공했다는 메세지가 표시되었다. 

![](/images/burp-academy-serial-3-success.png)