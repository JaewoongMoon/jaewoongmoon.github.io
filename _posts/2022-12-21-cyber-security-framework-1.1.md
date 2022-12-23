---
layout: post
title: "NIST Cyber Security Framework (CSF) Version 1.1"
categories: [보안프레임워크]
tags: tags: [보안프레임워크, CSF, Cyber Security Framework]
---

# 배경/개요 
- 미국 NIST 에서 2018년에 발표한 보안 프레임워크이다. 
- 최근 핫한 서플라인 체인 보안에 관한 내용이 있다고 하여 관심을 가지게 되었다. 
- 따라서 일단 서플라이 체인 보안에 대한 부분만 집중적으로 보려고 한다. 
- IPA의 번역본을 많이 참고하였다. 

# 버전 1.0과 차이점
- Greatly expanded explanation of using Framework for Cyber Supply Chain Risk Management purposes
- 사이버 공급망 위험 관리에서 프레임워크를 어떻게 사용하면 되는가에 대한 설명이 많이 추가되었다. 
- An expanded Section 3.3 Communicating Cybersecurity Requirements with Stakeholders helps users better understand Cyber Supply Chain Risk Management (SCRM), 
- "3.3 사이버 보안 요구 사항에 대한 이해 관계자와 커뮤니케이션하기" 에서는 **사이버 공급망 위험 관리 (SCRM : Supply Chain Risk Management)**에 대한 설명이 추가되었다. 
- while a new Section 3.4 Buying Decisions highlights use of the Framework in understanding risk associated with commercial off-the-shelf products and services. 
- 또한 새로운 섹션 "3.4 구매 결정" 에서는 프레임 워크를 활용하여 기성품 및 서비스의 위험을 이해하는 방법을 설명한다. 
- Additional Cyber SCRM criteria were added to the Implementation Tiers. 
- 구현 계층에 사이버 SCRM에 대한 새로운 기준이 추가되었다. 
- Finally, a Supply Chain Risk Management Category, including multiple Subcategories, has been added to the Framework Core.
- 프레임워크 코어에 공급망 리스크 관리 카테고리와 여러 하위 카테고리가 되었다. 

# 3.3 Communicating Cybersecurity Requirements with Stakeholders
타겟 프로파일에 대한 내용이 반복되어 등장한다. 실제로는 어떤 내용인지 궁금하다. 

- The Framework provides **a common language** to communicate requirements among interdependent stakeholders responsible for the delivery of essential critical infrastructure products and services. Examples include:
프레임워크는 필수적인 중요한 인프라 제품 및 서비스 제공을 책임지는 서로 의존하는 이해관계자들 간에 요구사항에 대한 커뮤니케이션을 가능하게 하는 **공통언어**를 제공한다. 다음과 같은 예가 있다. 

- An organization may use **a Target Profile** to express cybersecurity risk management requirements to an external service provider (e.g., a cloud provider to which it is exporting data).
조직은 외부 서비스 공급자 (예 : 데이터를 내보내는 클라우드 공급자) 에게 사이버 보안 위험 관리의 요구 사항을 전달하기 위해 **목표 프로파일**을 사용할 수 있다.

- An organization may express its cybersecurity state through **a Current Profile** to report results or to compare with acquisition requirements.
조직은 자신의 사이버 보안 상태를 보고하거나 조달 요구사항과 비교할 수 있도록 **현재 프로파일**을 사용하여 사이버 보안 상태를 나타낼 수 있다.

- A critical infrastructure owner/operator, having identified an external partner on whom that infrastructure depends, may use a Target Profile to convey required Categories and Subcategories.
중요 인프라 사업자 및 운영자는 (자신의) 인프라가 의존하는 외부 파트너를 식별하고, 카테고리와 하위 카테고리를 전달하기 위해 목표 프로파일을 사용할 수 있다.

- A critical infrastructure sector may establish a Target Profile that can be used among its constituents as an initial baseline Profile to build their tailored Target Profiles.
중요 인프라 분야에서는 각 구성 조직이 활용할 수있는 초기 베이스라인 프로파일로서 업계 고유의 목표 프로파일을 작성할 수 있다.

- An organization can better manage cybersecurity risk among stakeholders by assessing their position in the critical infrastructure and the broader digital economy using Implementation Tiers.
조직은 구현 계층을 사용하여 중요한 인프라 및 보다 광범위한 디지털 경제에 자신의 입장을 평가함으로써 이해 관계자 간의 사이버 보안 위험을 보다 잘 통제할 수 있다.

- Communication is especially important among stakeholders up and down supply chains.
공급망의 이해 관계자 간의 커뮤니케이션은 특히 중요하다. 

- Supply chains are complex, globally distributed, and interconnected sets of resources and processes between multiple levels of organizations. 
서플라이체인은 복잡하고, 전 세계적으로 분산되고, 여러 계층의 조직에 걸쳐 서로 연결되어 있다.

- Supply chains begin with the sourcing of products and services and extend from the design, development, manufacturing, processing, handling, and delivery of products and services to the end user.
공급망은 공급업체의 결정부터 시작하여 설계, 개발, 제조, 가공, 취급, 최종 사용자에게 제품 및 서비스 제공에 이르기까지 다양하다. 

- Given these complex and interconnected relationships, supply chain risk management (SCRM) is a critical organizational function.
이러한 복잡한 상호 관계를 고려하면 공급망 위험 관리 (SCRM)는 조직의 중요한 기능 중 하나이다. 

- Cyber SCRM is the set of activities necessary to manage cybersecurity risk associated with external parties. 
사이버 SCRM은 외부 관계자에 대한 사이버 보안 위험 관리에 필요한 일련의 이다. 

- More specifically, cyber SCRM addresses both the cybersecurity effect an organization has on external parties and the cybersecurity effect external parties have on an organization.
보다 구체적으로, 사이버 SCRM은 조직이 외부 관계자에게 미치는 사이버 보안상의 영향과 외부 관계자가 조직에 미치는 사이버 보안상의 영향을 모두 다룬다.

- A primary objective of cyber SCRM is to identify, assess, and mitigate “products and services that may contain potentially malicious functionality, are counterfeit, or are vulnerable due to poor manufacturing and development practices within the cyber supply chain.” Cyber SCRM activities may include:
• Determining cybersecurity requirements for suppliers,
• Enacting cybersecurity requirements through formal agreement (e.g., contracts),
• Communicating to suppliers how those cybersecurity requirements will be verified and validated,
• Verifying that cybersecurity requirements are met through a variety of assessment methodologies, and
• Governing and managing the above activities

사이버 SCRM의 주요 목적은 "사이버 공급망의 저품질 제조 및 개발 관행으로 인해 잠재적으로 유해한 기능을 포함 할 수있는 위조되거나 취약한 제품 및 서비스"를 식별하고 평가, 억제하는 것이다. 사이버 SCRM 활동에는 다음이 포함된다. 
• 공급자에 대한 사이버 보안 요구 사항을 결정하기.
• 사이버 보안 요구 사항을 공식 합의(예: 계약)로 정한다.
• 이러한 사이버 보안 요구 사항이 어떻게 검증되고 인증되는지에 대해 공급 업체와 의사 소통한다. 
• 다양한 평가 기법을 사용하여 사이버 보안 요구 사항이 충족되었는지 확인한다. 
• 위 활동의 통제, 관리





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


# 참고
- 원문: https://www.nist.gov/cyberframework/framework-documents
- 일본어 번역: https://www.ipa.go.jp/files/000071204.pdf
- 