---
layout: post
title: "NIST Cyber Security Framework (CSF) Version 1.1"
categories: [보안프레임워크]
tags: [보안프레임워크, CSF, Cyber Security Framework]
toc: true
---

# 배경/개요 
- 사이버 세큐리티 프레임워크 (Cyber Security Framework, CSF)는 미국 국립 표준기술 연구소(NIST) 에서 만든 보안 대책 프레임워크이다. 
- 2014년에 버전 1.0이, 2018년에 버전 1.1이 발표되었다. 
- 상세한 기술적 내용보다는 사이버 공격에 대한 조직 및 관리쪽 대책에 특화된 내용이다. 참고로 사이버 공격에 대한 기술쪽에 특화된 내용은 CIS Controls 를 참고하면 된다. 
- 버전1.1에는 최근 핫한 서플라인 체인 보안에 관한 내용이 있다고 하여 관심을 가지게 되었다. 
- 따라서 일단 서플라이 체인 보안에 대한 부분만 집중적으로 보려고 한다. 
- IPA의 번역본을 많이 참고하였다. 

# 버전 1.0과 차이점
- 사이버 공급망 위험 관리에서 프레임워크를 어떻게 사용하면 되는가에 대한 설명이 많이 추가되었다. 
- "3.3 사이버 보안 요구 사항에 대한 이해 관계자와 커뮤니케이션하기" 에서는 **사이버 공급망 위험 관리 (SCRM : Supply Chain Risk Management)**에 대한 설명이 추가되었다. 
- 또한 새로운 섹션 "3.4 구매 결정" 에서는 프레임 워크를 활용하여 기성품 및 서비스의 위험을 이해하는 방법을 설명한다. 
- 구현 계층에 사이버 SCRM에 대한 새로운 기준이 추가되었다. 
- 프레임워크 코어에 공급망 리스크 관리 카테고리와 여러 하위 카테고리가 되었다. 

# 3.3 사이버 보안 요구 사항에 대해 이해 관계자와 커뮤니케이션하기 (Communicating Cybersecurity Requirements with Stakeholders) 

목표 프로파일(Target Profile) 에 대한 내용이 반복되어 등장한다. 목표 프로파일이란 구매하고자 하는 제품에 요구하는 보안 수준을 상세 항목 및 숫자로 표현한 것이라고 이해하고 있다. 다음은 번역한 부분이다. 

- 프레임워크는 필수적인 중요한 인프라 제품 및 서비스 제공을 책임지는 서로 의존하는 이해관계자들 간에 요구사항에 대한 커뮤니케이션을 가능하게 하는 **공통언어**를 제공한다. 다음과 같은 예가 있다. 
- 조직은 외부 서비스 공급자 (예 : 데이터를 내보내는 클라우드 공급자) 에게 사이버 보안 위험 관리의 요구 사항을 전달하기 위해 **목표 프로파일**을 사용할 수 있다.
-조직은 자신의 사이버 보안 상태를 보고하거나 조달 요구사항과 비교할 수 있도록 **현재 프로파일**을 사용하여 사이버 보안 상태를 나타낼 수 있다.
- 중요 인프라 사업자 및 운영자는 (자신의) 인프라가 의존하는 외부 파트너를 식별하고, 카테고리와 하위 카테고리를 전달하기 위해 목표 프로파일을 사용할 수 있다.
- 중요 인프라 분야에서는 각 구성 조직이 활용할 수있는 초기 베이스라인 프로파일로서 업계 고유의 목표 프로파일을 작성할 수 있다.
- 조직은 구현 계층을 사용하여 중요한 인프라 및 보다 광범위한 디지털 경제에 자신의 입장을 평가함으로써 이해 관계자 간의 사이버 보안 위험을 보다 잘 통제할 수 있다.
- 공급망의 이해 관계자 간의 커뮤니케이션은 특히 중요하다. 
- 서플라이체인은 복잡하고, 전 세계적으로 분산되고, 여러 계층의 조직에 걸쳐 서로 연결되어 있다.
- 공급망은 공급업체의 결정부터 시작하여 설계, 개발, 제조, 가공, 취급, 최종 사용자에게 제품 및 서비스 제공에 이르기까지 다양하다. 
- 이러한 복잡한 상호 관계를 고려하면 공급망 위험 관리 (SCRM)는 조직의 중요한 기능 중 하나이다. 
- **사이버 SCRM**은 외부 관계자에 대한 사이버 보안 위험 관리에 필요한 일련의 행동의 모음이다. 
- 보다 구체적으로, 사이버 SCRM은 조직이 외부 관계자에게 미치는 사이버 보안상의 영향과 외부 관계자가 조직에 미치는 사이버 보안상의 영향을 모두 다룬다.
- 사이버 SCRM의 주요 목적은 "사이버 공급망의 저품질 제조 및 개발 관행으로 인해 잠재적으로 유해한 기능을 포함 할 수있는 위조되거나 취약한 제품 및 서비스"를 식별하고 평가, 억제하는 것이다. 사이버 SCRM 활동에는 다음이 포함된다.   
• 공급자에 대한 사이버 보안 요구 사항을 결정하기.   
• 사이버 보안 요구 사항을 공식 합의(예: 계약)로 정한다.   
• 이러한 사이버 보안 요구 사항이 어떻게 검증되고 인증되는지에 대해 공급 업체와 의사 소통한다.    
• 다양한 평가 기법을 사용하여 사이버 보안 요구 사항이 충족되었는지 확인한다.    
• 위 활동의 통제, 관리를 수행한다.   

- 그림 3에서 볼 수 있듯이 사이버 SCRM은 기술 공급 업체 / 구매자, 정보 기술 (IT), 산업용 제어 시스템 (ICS), 사이버 물리학 시스템 (CPS) 및 사물 인터넷 (IOT)을 포함한 연결 장비 일반과 같은 최소한의 기술만을 이용하는 비기술계 공급자/바이어가 포함된다. 
- 그림 3은 특정 시점의 조직 상태를 보여준다. 그러나 정상적인 영업 활동을 통해 대부분의 조직은 다른 조직이나 최종 사용자와의 관계에서 업스트림 공급 업체 또는 다운스트림 구매자가 될 수 있다.

![그림 3](/images/cyber-supply-chain-relationships.png)

- 조직의 사이버 보안 생태계는 그림 3에 표시된 당사자로 구성된다. 
- 이러한 관계는 중요한 인프라 및 보다 광범위한 디지털 경제에서 사이버 보안 위험에 대한 노력에서 사이버 SCRM의 역할의 중요성을 강조한다. 
- 이러한 관계, 각 당사자가 제공하는 제품 및 서비스, 각 당사자가 제공하는 리스크는 식별되어 조직의 방어·검출 기능과 대응·복구 계획에 반영되어야 한다.
- 위의 그림에서 "구매자(Buyer)"는 조직 (영리 및 비영리 조직 모두 포함)이 제공하는 제품 또는 서비스를 소비하는 사람 또는 조직을 의미한다. 
- "공급자(Supplier)"는 조직 내 목적을 위해 사용되는 제품 및 서비스 (예 : IT 인프라) 또는 구매자에게 제공되는 제품 또는 서비스에 포함 된 제품 및 서비스를 제공하는 사람을 의미한다. 
- 이 용어는 기술 제품, 서비스 및 비기술 제품 및 서비스 모두에 적용된다.
- 프레임워크 코어의 각 하위 카테고리를 검토하는 경우, 혹은 프로파일을 포괄적으로 검토하는 경우에, 프레임워크는 조직과 파트너에게 새로운 제품 및 서비스가 중요한 보안 성과를 달성할 수 있도록 보장하는 방법을 제공한다. 
- 먼저 상황에 적합한 성과를 선택하는 것(예: 개인정보(PII)의 송신, 기간서비스의 제공, 데이터인증서비스, 제품·서비스 품질)에 의해, 조직은 그 기준을 파트너가 만족할지 평가할 수 있다. 예를 들어, 운영 기술(OT)의 네트워크 통신 이상을 모니터링하는 시스템을 구매하는 경우, 가용성은 달성해야 할 중요한 사이버 보안 목표가 될 수 있으며, 기술 공급자의 평가는 이에 해당하는 하위 범주에 따라 수행되어야 한다 (예: ID.BE-4, ID.SC-3, ID.SC-4, ID.SC-5, PR.DS-4, PR.DS-6, PR .DS-7, PR.DS-8, PR.IP-1, DE.AE-5).

역주: 서브카테고리의 숫자는 보안레벨과는 상관이 없다. 요구되는 대책을 번호로 식별하고 있을 뿐이다. 따라서 여러개를 선택가능하다. 예를들어 위의 경우라면, ID.SC (Identity, Supply Chain Risk Management) 카테고리에서 ID.SC-3, ID.SC-4, ID.SC-5 가 선택되어 있다. ID.SC 의 서브카테고리는 다음과 같다. 
- ID.SC-1: 사이버 공급망의 위험 관리 프로세스가 조직의 이해 관계자에 의해 식별, 규정, 평가, 관리 및 승인되었다.
- ID.SC-2: 정보시스템, 컴포넌트, 서비스 공급업체 및 제3자인 파트너가 식별, 우선순위화 및 사이버 공급망의 위험 평가 프로세스에 의해 평가된다.
- ID.SC-3: 공급업체 및 제3자인 파트너와의 계약이 조직의 사이버 보안 프로그램 및 사이버 공급망의 리스크 관리 계획의 목적을 달성하기 위한 적절한 조치를 수행하는 데 활용된다.
- ID.SC-4: 공급업체 및 제3자인 파트너는 감사, 시험 결과 또는 기타 평가에 따라 계약상의 의무를 충족하거나 정기적으로 평가한다.
- ID.SC-5: 대응·복구 계획의 책정과 테스트가 공급자 및 제3자 제공자와 함께 실시된다. 

# 3.4 Buying Decisions
```
Since a Framework Target Profile is a prioritized list of organizational cybersecurity
requirements, Target Profiles can be used to inform decisions about buying products and
services. This transaction varies from Communicating Cybersecurity Requirements with
Stakeholders (addressed in Section 3.3) in that it may not be possible to impose a set of
cybersecurity requirements on the supplier. The objective should be to make the best buying
decision among multiple suppliers, given a carefully determined list of cybersecurity
requirements. Often, this means some degree of trade-off, comparing multiple products or
services with known gaps to the Target Profile.
Once a product or service is purchased, the Profile also can be used to track and address
residual cybersecurity risk. For example, if the service or product purchased did not meet all
the objectives described in the Target Profile, the organization can address the residual risk
through other management actions. The Profile also provides the organization a method for
assessing if the product meets cybersecurity outcomes through periodic review and testing
mechanisms.
```

# 부록 A. 프레임워크 코어
요구사항 항목(카테고리)을 나타낸다. 

![사이버세큐리티 프레임워크 코어](/images/cybersecurity-framework-core.png)

- 이 부록은 프레임 워크 코어, 즉 모든 중요한 인프라 분야에 공통적인 특정 사이버 보안 대책이 되는 기능, 카테고리, 서브 카테고리 및 참고 정보를 나열한다. 
- 본 부록의 프레임워크 코어의 기재는 실시에 관하여 구체적인 순서를 나타내지는 않고, 기재되어 있는 카테고리, 서브 카테고리, 참고 정보가 중요도순으로 기재되어 있는 것은 아니다. 
- 본 부록에 제시된 프레임워크 코어는 사이버 보안 위험을 관리하기 위한 대책의 일반적인 예이다. 
- 프레임워크는 포괄적이지는 않지만 확장 가능하며 조직, 산업 및 기타 당사자가 효율적으로 자체 사이버 보안 위험을 관리 할 수있는 서브 카테고리 및 참고 정보를 활용할 수 있다. 
- 대책은 프로파일 작성시에 프레임워크 코어로부터 선택할 수 있고, 추가의 카테고리, 서브카테고리, 참고 정보를 프로파일에 추가할 수도 있다.
- 조직의 리스크 관리 프로세스, 법규제 요구사항, 사업목적 및 임무, 조직에 부과되는 제약은 프로파일 작성 시 위에서 설명한 활동의 선택에 영향을 미친다. 
- 개인 정보는 보안 위험과 보호 조치를 평가할 때 카테고리에서 참조되는 데이터 또는 자산의 한 요소이다.
- 기능, 카테고리 및 서브 카테고리로 식별되는 목표 성과는 IT이든 ICS(Industrial Control Systems) 이든 동일하지만 운영 환경과 고려해야 할 사항은 다르다. 
- ICS는 개인의 건강과 안전에 대한 잠재적 위험과 환경에 대한 영향과 같은 물리적 세계에 직접적인 영향을 미친다. 
- 또한 ICS는 IT에 비해 성능과 신뢰성에 대한 독특한 요구 사항을 가지고 있으며 사이버 보안 대책을 구현할 때 안전성과 효율성을 목표로 할 필요가 있다.
- 사용의 용이성을 고려하여, 프레임워크 코어의 각 카테고리에는 개별 식별자가 할당된다. 
- 표 1에서 볼 수 있듯이 기능과 카테고리에는 각각 알파벳으로 표시된 개별 식별자가 할당된다. 
- 표 2의 각 카테고리 내의 서브 카테고리에는 숫자의 개별 식별자가 할당된다. 
- 참고 정보를 포함하여 본 프레임워크와 관련된 보충 자료는 아래의 NIST 웹 사이트를 참조한다. 
- http://www.nist.gov/cyberframework/
- 역주: 위 사이트에는 다운로드 받을 수 있는 엑셀파일이 있는데, 거기에 상세한 서브 카테고리가 기술되어 있다. 

# 참고
- 원문: https://www.nist.gov/cyberframework/framework-documents
- 일본어 번역: https://www.ipa.go.jp/files/000071204.pdf