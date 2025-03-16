---
layout: post
title: "MITRE-ATT&CK 프레임워크 정리"
categories: [보안일반]
tags: [보안일반]
toc: true
last_modified_at: 2024-05-14 12:10:00 +0900
---

# 개요
- ATT&CK 는 Adversarial Tactics, Techniques, and Common Knowledge (적의 전술, 테크닉, 공통지식)의 약자이다. 
- 간단하게 말하자면 적이 사용하는 전술과 테크닉을 파악하는 것을 도와주는 프레임워크이다. 
- 즉, 방어측에게 공격자에 대한 인사이트(공격자가 어디를 노릴 것이고, 어떤 행동을 할 것인지 등에 대한)를 준다고 할 수 있다. 
- 손자왈: **적을 알고**, 나를 알면, 백번 싸워도 위태롭지 않다. (敵を知り己を知れば百戦危うからず / If you know the enemy and know yourself, you need not fear the result of a hundred battles.)
- 데이비드 비아코가 제창한 "고통의 피라미드"에서 가장 공격억제에 효과적이라고 설명하는(정점에 위치하는) TTPs(전술,테크닉,기술)중에서 전술과 테크닉을 알려준다. 
- 종류는 네 가지가 있다. 
   - PRE-ATT&CK: 적이 공격하기 전에 사용하는 전술과 테크닉을 다룬다.
   - Mobile ATT&CK: iOS와 안드로이드를 사용하는 모바일 환경에서의 적의 전술과 테크닉을 다룬다. 
   - Enterprise ATT&CK: 기업 환경(시스템과 네트워크)에서의 적의 전술과 테크닉을 다룬다. 
   - ICS ATT&CK: 산업 컨트롤 시스템 (Industrial Control Systems (ICS))에서의 적의 전술과 테크닉을 다룬다. 
- 이 중에서 `Enterprise ATT&CK`에 중점을 두고 조사한다. 
- `Enterprise ATT&CK`에서는 적의 목표(why)를 14개의 전술(Tactics) 카테고리로 나누어, 각 카테고리별로 해당되는 테크닉을 소개하고 있다. 테크닉은 150개 이상이 존재한다. 
- 최근에는 테크닉이 더욱 세분화되어, 서브 테크닉도 소개해주고 있다. 서브테크닉은 270개 이상이 존재한다.
- ATT&CK는 록히드마틴이 개발한 `Cyber Kill Chain`을 대신할 수 있다고 한다. 

## 방어자의 이점: 사이버 킬체인
- 미국 군수업체 록히드마틴이 2011년 발표한 논문의 컨셉인 킬체인은 **인텔리전스 기반의 방어 모델**로 사이버보안에 도입되었고 이후 킬체인은 사이버공격 대응전략의 주된 개념으로 자리잡았다.
- 이 논문에서 지능형 지속 위협(APT)이라고 명명된 공격자는 맞춤형 악성코드와 제로데이 공격을 이용하기 때문에 안티바이러스와 패치 적용과 같은 기존의 취약점 중심 접근방식으로는 충분하지 않고 인텔리전스를 기반으로 하는 위협 중심 접근방식이 필요하다고 제안한다
- **침입 자체를 단일 이벤트가 아닌 단계적 진행으로 이해하면 목표 달성 전에 각 단계를 성공적으로 진행해야 하는 공격자보다 한 번의 방어로 공격을 와해할 수 있는 방어자가 우위를 점할 수 있다는 것이다.**
- 참고: http://www.igloosec.co.kr/pdf/igloosec_security_report_202201.pdf

# ATT&CK Matrix for Enterprise
표로 표현하면 다음과 같다. 

|No|Category|Description|Techniques|
|----|----|-----|-----|
|1|Reconnaissance (정찰)|타겟에 대한 정보를 모은다.|10|
|2|Resource Development (리소스개발)|공격을 위한 재료(리소스)를 인식하고 획득한다.|8|
|3|Initial Access(최초 억세스)| 네트워크나 시스템에 대한 최초의 억세스를 얻어낸다.|10|
|4|Execution (실행)|시스템상에서 악의적인 코드를 실행시킨다.|14|
|5|Persistence(유지)| 네트워크나 시스템으로의 억세스를 유지한다.|20|
|6|Privilege Escalation(권한상승)|네트워크나 시스템상에서 권한을 상승시킨다.|14|
|7|Defense Evasion(방어 회피)|보안 대책을 무효화시키거나 회피한다.|43|
|8|Credential Access(크레덴셜 접근)|시스템이나 데이터에 접근하기 위한 크레덴셜을 얻어낸다.|17|
|9|Discovery(발견)|네트워크에 존재하는 시스템을 찾거나 시스템에 대한 정보를 얻어낸다. |32|
|10|Lateral Movement(횡이동)|침해된 네트워크 상에서 다른 시스템으로 이동한다.|9|
|11|Collection(수집)|침해된 시스템들에 대한 정보를 모은다.|10|
|12|Command and Control(원격서버에 의한 조종) | 침해된 시스템들을 원격서버와 연결시켜 조종할 수 있게 한다.|17|
|13|Exfiltration(탈출)|침해된 시스템에서 훔친 데이터를 전송한다.|9|
|14|Impact(충격)|공격자의 목표를 달성하기 위한 행동을 수행한다.|14|


# 관련툴
몇 가지 유용한 툴을 무료로 제공해준다. 

## ATT&CK Navigator
- ATT&CK 프레임워크를 자유롭게 수정하거나 할 수 있는 웹 툴이다.  
- https://mitre-attack.github.io/attack-navigator/
- 예를들면 다음과 같이 특정 테크닉에 색을 칠해서 저장하거나 할 수 있다. 

![](/images/att-and-ck-navigator-example.png)

## MITRE Cyber Analytics Repository (CAR)
- 사이버 보안에 대한 각종 분석 레포트들을 모아 놓은 사이트이다.
- https://car.mitre.org/analytics/
- 예를 들면, SMB 이벤트 모니터링(CAR-2013-01-003)에 대한 정보 등을 알 수 있다. 

## Red Canary Atomic Red Team
- 악의적인 행동을 시뮬레이션할 수 있다. 
- 특정 영역에서 방어측은 자신의 방어책(safeguards)이 유효한지 테스트해볼 수 있다. 
- TTP에서 ATT&CK 매트릭스에서는 다루지 않고 있는 Procedure(기술)에 대한 부분을 제공해준다. 
- 자동화된 테스트다. 각 테스트는 yaml파일로 기술되어 있다. 
- 테스트를 위해서는 대상 시스템을 준비해야 한다. (자신이 준비한 시스템이 아니라면 허가를 얻어야 한다.)
- 이거 되게 흥미롭다. 한번 사용해보고 싶다. 
- https://github.com/redcanaryco/atomic-red-team
- https://redcanary.com/atomic-red-team/
- 참고로 ATT&CK 에서 제공하는 `칼데라`(https://caldera.mitre.org/)라는 것도 비슷한 기능인 것 같다. 

# 참고 
- https://en.wikipedia.org/wiki/ATT%26CK
- https://attack.mitre.org/
- https://www.wallarm.com/what/what-is-the-mitre-attck-framewor