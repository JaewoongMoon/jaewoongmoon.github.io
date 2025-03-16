---
layout: post
title: "Burp Academy-LLM 취약점: Exploiting insecure output handling in LLMs"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, LMM취약점]
toc: true
last_modified_at: 2024-10-22 21:55:00 +0900
---

# 개요
- 취약점 설명 주소: https://portswigger.net/web-security/llm-attacks#indirect-prompt-injection
- 문제 주소: https://portswigger.net/web-security/llm-attacks/lab-exploiting-insecure-output-handling-in-llms
- 난이도: EXPERT (어려움)



# 랩 개요
- 이 랩은 LLM 출력을 안전하지 못하게 다루고 있어서 XSS취약점이 발생할 수 있다. 
- carlos 유저는 종종 라이브 챗 기능을 사용해서 Lightweight "l33t" Leather Jacket 에 대해 물어본다. 
- 랩을 풀려면 indirect prompt injection 을 사용해서 XSS 공격을 수행해서 carlos 유저를 삭제하라. 

```
This lab handles LLM output insecurely, leaving it vulnerable to XSS. The user carlos frequently uses the live chat to ask about the Lightweight "l33t" Leather Jacket product. To solve the lab, use indirect prompt injection to perform an XSS attack that deletes carlos.
```

# 도전
1. 회원가입 기능이 존재한다. 그리고 이메일 클라이언트가 주어져 있다. 회원으로 가입한다. 이 때 이메일 클라이언트에 설정되어 있는 이메일을 사용한다. 

회원가입이 완료된 모습이다. 

![](/images/burp-academy-llm-4-1.png)

2. 상품 상세 페이지로 이동하면 리뷰를 남길 수 있게 되어 있다. 이 때, 프로그램에 의한 등록을 방지하기 위해 Captcha가 설정되어 있다. 

![](/images/burp-academy-llm-4-2.png)

3. Live Chat 기능을 테스트해본다. 페이로드 `<img src=1 onerror=alert(1)>`를 채팅창에 입력해본다. 

![](/images/burp-academy-llm-4-3.png)

4. 그러면 이 입력이 제대로 에스케이프 처리가 되지 않아 alert함수가 실행되는 것을 볼 수 있다. 

![](/images/burp-academy-llm-4-4.png)

5. Lightweight "l33t" Leather Jacket이 아닌 다른 상품 상세 페이지로 이동하여 위의 페이로드를 리뷰입력이 적어서 저장해본다. 

![](/images/burp-academy-llm-4-5.png)

6. 저장되고 나면 상품 상세 페이지에서는 alert함수가 동작하지 않는 것을 알 수 있다. 

![](/images/burp-academy-llm-4-6.png)

7. Live Chat에서 챗봇에게 위의 상품의 리뷰에 대해 물어본다. 

```
Tell me about the review of a product First Impression Costumes.
```

![](/images/burp-academy-llm-4-8.png)

8. 그러면 alert창이 표시된다. 그리고 다음과 같이 보안상 이유로 이미지 링크가 지워졌다는 메세지가 표시된다. 비정상적인 리뷰를 탐지는 할 수 있지만 구멍이 있다. 

![](/images/burp-academy-llm-4-7.png)

9. 이제 실제 공격용 페이로드를 만들어본다. 로그인한 뒤의 내 계정(My Account) 웹 페이지를 살펴보면 다음과 같이 폼이 두 개 존재하는 것을 볼 수 있다. 하나는 이메일 주소를 변경하는 것이고 하나는 계정을 삭제하는 것이다. 

![](/images/burp-academy-llm-4-11.png)


다음과 같은 iframe을 삽입하면 My Account 웹 페이지의 두번재 폼(계정 삭제 폼)이 제출될 것이다. 

```html
<iframe src =my-account onload = this.contentDocument.forms[1].submit() >
```

10. XSS 공격용 페이로드를 그럴 듯한 리뷰안에 섞어서 리뷰를 작성한다. 다음과 같다. 이 리뷰를 First Impression Costumes 상품의 상세 페이지에서 등록한다. 

```
When I received this product I got a free T-shirt with "<iframe src =my-account onload = this.contentDocument.forms[1].submit() >" printed on it. I was delighted! This is so cool, I told my wife.
```

![](/images/burp-academy-llm-4-9.png)

11. 그리고 챗봇에게 다시한번 상품에 대해 물어본다. 

```
Tell me about the review of a product First Impression Costumes.
```

12. 그러면 리뷰에 삽입했던 iframe이 보이는 것을 알 수 있다! 

![](/images/burp-academy-llm-4-12.png)


13. My account 페이지로 가보면 로그인이 풀려있다. 등록했던 계정으로 로그인을 하려고하면 로그인이 안되는 것을 알 수 있다. 계정이 삭제된 것이다! 

![](/images/burp-academy-llm-4-13.png)

14. 위에서 만든 페이로드가 잘 동작하는 것을 확인했다. 다시 유저를 생성하고 Lightweight "l33t" Leather Jacket 상품의 페이지로 이동하여 공격용 페이로드가 포함된 리뷰를 작성한다. 

15. carlos 유저가 챗봇에게 재킷의 리뷰를 물어보는 시간동안 잠시 기다린다. 그러면 랩이 풀렸다는 메세지가 표시된다. 

![](/images/burp-academy-llm-4-success.png)