---
layout: post
title: "Dependency Confusion 조사"
categories: [보안취약점]
tags: [보안취약점, Dependency Confusion]
toc: true
---

# Dependency Confusion 이란?
```Dependency confusion (also known as dependency repository hijacking, substitution attack, or repo jacking for short) is a software supply chain attack that substitutes malicious third-party code for a legitimate internal software dependency. ```

- 서플라이 체인 공격이다.
- 개인적인 생각으로는 소프트웨어 서플라이 체인 공격중에서 가장 중요할 것 같다. 
- 어떤 내부 라이브러리 (공개된 라이브러리가 아닌, 예를들어 회사내에서만 사용하는 라이브러리 등) 대신에 동일한 이름의 악의적인 라이브러리를 실행시키는 공격이다. 
- 대부분의 패키지 매니저가 동일한 이름의 라이브러리라면 내부 레지스트리보다 공개 레지스트리를 우선하기 때문에 발생한다. 
- 내부 라이브러리와 동일한 이름의 라이브러리가 공개 레지스트리에 등록되지 않은 상태라면 노려질 가능성이 있다. 

# POC 시나리오
Python 사용

- 내부 라이브러리를 사용하는 샘플을 개발
- 동일한 이름의 해킹용 라이브러리를 개발
- 퍼블릭 레지스트리에 해킹용 라이브러리를 업로드
- 샘플을 다시한번 실행해서 공격용 코드가 실행되는지 확인



## 테스트 결과 
- 기존에 이미 라이브러리를 설치한 경우에는 해당 라이브러리를 사용하므로 Dependency Confusion 공격이 성립하지 않았다. 
- pip 으로 새로운 라이브러리를 설치하고, 그 라이브러리를 사용할 때 코드가 실행되었다. 
- 만약 빌드 서버같은 곳에서 항상 새로운 버전의 라이브러리를 사용하기 위해 빌드시 처음에 pip install 을 실행한다면 이 공격에 취약할 것으로 생각된다. 

# 대책 /완화책 
## 패키지매니저 설정을 변경
패키지매니저의 설정을 변경해서 공개 레지스트리보다 내부 레지스트리를 우선하도록 설정을 변경한다. 

## 공개 레지스트리 감시 
내부 라이브러리와 동일한 이름의 라이브러리가 공개 레지스트리에 등록되어 있는지 확인한다. 등록되어 있다면 삭제 요청한다. 

## 선점하기
내부 라이브러리와 동일한 이름의 라이브러리를 공개 레지스트리에 등록해둔다. 이름만 등록해둘지 코드까지 등록해둘지는 선택한다. 
- 장점: 이 공격에 대한 방어가 가능하다. 
- 단점: 내부 라이브러리 이름이 공개된다. 코드까지 공개할경우는 코드도 공개되어 버린다. 


# 탐지법
악용될 가능성이 있는 부분을 어떻게 찾을 수 있을까? 즉, 전혀 사전 지식이 없는 상태에서 어떻게 내부 라이브러리가 사용된다는 것을 알 수 있을까?
- 공식 라이브러리를 조사하고 싶다면, 그 라이브러리를 다운로드 받은 후 패키지 구성 정보 파일(ex) package.json 등) 을 살펴보는 방법이 있을 것 같다.
- node로 개발한 웹 페이지라면, 웹 페이지를 디버거 툴로 보면, 어떤 라이브러리가 사용되고 있는지가 보인다. 이 것을 보고 내부 라이브러리를 사용하고 있는지 알 수 있다. (사용하고 있는 라이브러리를 공식 리포지터리에서 검색한다. 만약 검색되지 않는 라이브러리가 있다면 그 것을 내부 라이브러리로 판단할 수 있을 것이다. )

# 툴을 이용한 탐지법
- 이미 Snyk 와 같은 툴은 Dependency Confusion 취약점을 탐지하는 기능이 있다고 한다. 
- https://snyk.io/blog/detect-prevent-dependency-confusion-attacks-npm-supply-chain-security/

# Node.js 
- Scope라는 개념이 있어서 이 것을 사용하면 상당부분 완화할 수 있을 것 같다. 
- https://github.blog/2021-02-12-avoiding-npm-substitution-attacks/
- https://github.com/ossf/package-manager-best-practices/blob/main/published/npm.md#private-packages
- 탐지해주는 모듈이 있다. https://www.npmjs.com/package/snync
- 

# 참고 링크 
- https://www.activestate.com/resources/quick-reads/dependency-confusion/#:~:text=Dependency%20confusion%20(also%20known%20as,a%20legitimate%20internal%20software%20dependency.
- https://snyk.io/blog/detect-prevent-dependency-confusion-attacks-npm-supply-chain-security/