---
layout: post
title: "네거티브 grep 사용법"
categories: [Linux, 로그확인]
tags: [Linux, 로그확인]
toc: true
---

# 개요
- 웹 서버 로그등을 확인할 때, 특정 문자열은 제외한 부분을 확인하고 싶을 때가 있다. (Negative Grep)
- 보통은 특정 문자열이 포함되어 있는 부분을 확인하는 경우가 많다. `cat logfile.txt | grep xxxxx`
- 이 와는 반대로 동작하는 grep은 어떻게 할 수 있을까?

# 상세
구글검색해보면 [여기](https://stackoverflow.com/questions/3548453/negative-matching-using-grep-match-lines-that-do-not-contain-foo)를 보면 `-v` 옵션을 쓰면 이 동작이 가능하다고 한다. 

```sh
cat logfile.txt | grep -v 제외하고싶은문자열
```

리다이렉션을 이어서 사용해도 된다. 

```sh
cat logfile.txt | grep -v 제외하고싶은문자열1 | grep -v 제외하고싶은문자열2
```