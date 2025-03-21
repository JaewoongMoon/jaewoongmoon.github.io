---
layout: post
title: "OWASP LLM Top 10 개요"
categories: [보안취약점, OWASP, LLM Top10]
tags: [보안취약점, OWASP, LLM Top10]
toc: true
last_modified_at: 2024-10-08 21:55:00 +0900
---


# 개요
- LLM (Large Language Model) 의 Top 10 취약점을 정리한다. 

# 기본 지식 (관련 용어, 개념등)
## 프롬프트(Prompt)
- 사용자 또는 시스템에서 제공하는 입력으로, LLM에게 특정 작업을 수행하도록 요청하는 지시문이다. 
- 프롬프트는 질문, 명령, 문장 시작 부분 등 다양한 형태를 취할 수 있으며, LLM의 응답을 유도하는 데 중요한 역할을 한다.
- 프롬프트는 사용자와 언어 모델 간의 대화에서 질문이나 요청의 형태로 제시되는 입력문이다.이는 모델이 어떤 유형의 응답을 제공할지 결정하는 데 중요한 역할을 한다.
- 사용자가 제공하는 입력을 `유저 프롬프트`, 시스템이 제공하는 입력을 `시스템 프롬프트`라고 한다. 
- 시스템 프롬프트를 사용해서 유저와의 상호작용 중에 모델이 사용할 컨텍스트, 범위, 보안가드레일 또는 출력 형식을 미리 정의할 수 있다. 한마디로 LLM에서 허용되는 응답에 대한 구조를 제공한다. 

## LLM을 사용한 어플리케이션 구조
다음과 같은 구조를 가진다. 유저는 LLM을 통해서 직접 접근할 수 없는 Sytem API를 사용할 수 있다. 이로 인해서 발생하는 취약점을 SSRF와 비슷한 성격을 가진다. 

              
유저 입력 <---> (firewall) WebSite <---> LLM (Chat bot) <---> Sytem API 
            

# LLM 취약점 Top 10 
## LLM 01. Prompt Injection 
공격자가 조작한 입력을 통해 LLM을 조작하여 의도하지 않은 동작을 유발한다. 이는 시스템 프롬프트를 덮어쓰거나 외부 입력을 조작하는 방식으로 이루어진다.

두 종류가 있다. "Direct Prompt Injection"과 "Indirect Prompt Injection"이다. 

**Direct Prompt Injection (직접 프롬프트 주입, A.K.A jailbreaking)**
- 이는 "jailbreaking"으로도 알려져 있다. 악의적인 유저가 시스템 프롬프트를 덮어쓰는 거나 노출시킬 때 일어난다. 


**Indirect Prompt Injection (간접 프롬프트 주입)**
- LLM이 공격자가 컨트롤 가능한 외부 소스 (웹 사이트나 파일등)를 입력으로 받아들이는 경우에 발생한다. 
- 공격자는 외부 소스에 프롬프트 인젝션을 삽입하여 LLM과의 대화 컨텍스트를 하이재킹할 수 있다. 
- 이로 인해 LLM 출력 스티어링이 덜 안정적이 되어 공격자가 사용자나 LLM이 액세스할 수 있는 추가 시스템을 조작할 수 있다. 
- 또한 간접 프롬프트 주입은 LLM에서 텍스트를 구문 분석하는 한, 사람이 보거나 읽을 필요가 없다.

### 취약점의 예
1. 악의적인 사용자가 LLM에 직접 프롬프트 주입을 작성하여 애플리케이션 작성자의 시스템 프롬프트를 무시하고 대신 비공개, 위험 또는 기타 바람직하지 않은 정보를 반환하는 프롬프트를 실행하도록 지시한다.(시스템 프롬프트 덮어쓰기)
2. 사용자가 LLM을 사용하여 간접 프롬프트 주입이 포함된 웹페이지를 요약합니다. 그러면 LLM이 사용자에게 민감한 정보를 요청하고 JavaScript 또는 Markdown을 통해 추출을 수행한다.
3. 악의적인 사용자가 간접 프롬프트 주입이 포함된 이력서를 업로드한다. 이 문서에는 LLM이 사용자에게 이 문서가 훌륭하다는 것을 알리도록 하는 지침이 포함된 프롬프트 주입이 포함되어 있다. 예를 들어 이 사람은 직무에 적합한 후보자라고 하는 식이다. 내부 사용자가 LLM을 통해 문서를 실행하여 문서를 요약한다. LLM의 출력은 이 문서가 훌륭하다는 정보를 반환한다.
4. 사용자가 전자 상거래 사이트에 연결된 플러그인을 활성화한다. 방문한 웹사이트에 포함된 악성 지침이 이 플러그인을 악용하여 무단 구매로 이어진다.
5. 방문한 웹사이트에 포함된 악성 지침과 콘텐츠가 다른 플러그인을 악용하여 사용자를 사기친다.

### 방어책 

명령어와 외부 데이터를 서로 분리하지 않는 LLM의 특성으로 인해 프롬프트 인젝션 취약점이 발생할 수 있다. LLM은 자연어를 사용하기 때문에 두 가지 형태의 입력을 모두 사용자가 제공한 것으로 간주한다. 결과적으로 LLM 내에서 완벽하게 방지할 수 있는 방법은 없지만 다음과 같은 조치를 통해 프롬프트 주입의 영향을 완화할 수 있다:

1. LLM의 백엔드 시스템에 대한 액세스 권한 제어를 시행한다. 플러그인, 데이터 액세스 및 기능 수준 권한과 같은 확장 가능한 기능에는 LLM에 자체 API 토큰을 제공한다. 최소 권한 원칙을 따라 LLM을 필요 최소 수준의 액세스 권한으로만 제한한다. 
2. 확장된 기능의 흐름에 인간에 의한 확인을 추가한다. 예를 들어 이메일 전송 또는 삭제와 같은 권한 있는 작업을 수행할 때는 애플리케이션에서 먼저 사용자의 승인을 받도록 한다. 이렇게 하면 간접적인 프롬프트 주입으로 인해 사용자 모르게 또는 사용자 동의 없이 무단 작업이 수행될 가능성이 줄어든다. 
3. 사용자 프롬프트에서 외부 콘텐츠를 분리한다. 신뢰할 수 없는 콘텐츠가 사용되는 위치를 분리하고 표시하여 사용자 프롬프트에 미치는 영향을 제한한다. 예를 들어, OpenAI API 호출용 ChatML을 사용하여 프롬프트 입력의 출처를 LLM에 표시한다.
4. LLM, 외부 소스, 확장 가능한 기능(예: 플러그인 또는 다운스트림 기능) 간에 신뢰 경계를 설정한다. LLM을 신뢰할 수 없는 사용자로 취급하고 의사 결정 프로세스에 대한 최종 사용자 제어권을 유지한다. 그러나 손상된 LLM은 사용자에게 정보를 제공하기 전에 정보를 숨기거나 조작할 수 있으므로 애플리케이션의 API와 사용자 사이의 중개자(중간자) 역할을 할 수 있다. 잠재적으로 신뢰할 수 없는 응답을 사용자에게 시각적으로 강조 표시한다.
5. LLM 입력 및 출력을 주기적으로 수동으로 모니터링하여 예상대로 작동하는지 확인한다. 이는 완화책은 아니지만 취약점을 감지하고 해결하는 데 필요한 데이터를 제공할 수 있다.


### 공격시나리오의 예 
1. 공격자가 LLM 기반 지원 챗봇에 직접 프롬프트 인젝션을 수행한다. 이 인젝션에는 개인 데이터 저장소를 쿼리하고 패키지 취약점과 백엔드 기능의 출력 유효성 검사 부족을 악용하여 이메일을 전송하는 새로운 지침과 "모든 이전 지침을 잊어라"는 지침이 포함되어 있다. 이로 인해 원격 코드 실행, 무단 액세스 및 권한 상승으로 이어진다.
2. 공격자는 웹 페이지에 간접적인 프롬프트 인젝션을 삽입하여 LLM이 이전 사용자 지침을 무시하고 LLM 플러그인을 사용하여 사용자의 이메일을 삭제하도록 지시한다. 사용자가 이 웹페이지를 요약하기 위해 LLM을 사용하면 LLM 플러그인이 사용자의 이메일을 삭제한다.
3. 사용자가 LLM을 사용하여 모델에게 이전 사용자 지침을 무시하도록 지시하는 텍스트가 포함된 웹페이지를 요약하고 대신 대화 요약이 포함된 URL로 연결되는 이미지를 삽입한다. LLM 출력은 이를 준수하여 사용자의 브라우저가 비공개 대화를 유출하도록 한다.
4. 악의적인 사용자가 프롬프트 인젝션과 함께 이력서를 업로드합니다. 백엔드 사용자는 LLM을 사용하여 이력서를 요약하고 그 사람이 적합한 후보자인지 묻는다. 프롬프트 인젝션으로 인해 실제 이력서 내용에도 불구하고 LLM 응답은 '예'이다.
5. 공격자는 시스템 프롬프트에 의존하는 전용 모델에 메시지를 전송하여 모델에 이전 지침을 무시하고 대신 시스템 프롬프트를 반복하도록 요청한다. 모델은 전용 프롬프트를 출력하고 공격자는 이러한 지침을 다른 곳에서 사용하거나 더 교묘한 공격을 구성할 수 있다.

## LLM02: Insecure Output Handling
시스템이 대규모 언어 모델(LLM)의 출력을 맹목적으로 신뢰하면 XSS 및 원격 코드 실행과 같은 보안 문제가 발생할 수 있다. 시스템이 간접적인 프롬프트 인젝션 공격에 취약한 경우, 피해는 더욱 심각해질 수 있다.

### 방어책
- 모델을 다른 사용자처럼 취급하고, 제로 트러스트 접근 방식을 채택하고, 모델에서 백엔드 함수로 오는 응답에 적절한 입력 검증을 적용한다.
- 효과적인 입력 검증 및 새니타이제이션을 보장하기 위해 OWASP ASVS(Application Security Verification Standard) 가이드라인을 따른다.
- JavaScript 또는 Markdown에 의한 원치 않는 코드 실행을 완화하기 위해 모델 출력을 다시 인코딩하여 사용자에게 출력합니다. OWASP ASVS는 출력 인코딩에 대한 자세한 지침을 제공한다.

## LLM03: Training Data Poisoning
간접적인 프롬프트 인젝션 공격(Indirect prompt injection)의 한 종류이다. 이 취약점은 머신러닝 모델 학습에 사용되는 데이터가 변조될 때 발생하며, 편향(바이어스)으로 이어질 수 있다. 이는 모델의 유효성에 영향을 미쳐 유해한 결과를 초래하고, LLM을 사용하는 브랜드의 평판을 훼손할 수 있다.

### 방어책
1. 특히 외부에서 소싱한 경우 교육 데이터의 공급망을 확인하고 "ML-BOM"(기계 학습 자재 목록) 방법론을 통해 증명을 유지하고 모델 카드를 확인한다. 
2. 사전 교육, 미세 조정 및 임베딩 단계에서 얻은 대상 데이터 소스와 포함된 데이터의 올바른 적법성을 확인한다. 
3. LLM과 통합할 애플리케이션에 대한 사용 사례를 확인한다. 별도의 교육 데이터를 통해 다른 모델을 만들거나 다른 사용 사례에 대한 미세 조정을 통해 정의된 사용 사례에 따라 보다 세부적이고 정확한 생성 AI 출력을 만든다.
4. 네트워크 제어를 통한 충분한 샌드박싱이 있는지 확인하여 모델이 기계 학습 출력을 방해할 수 있는 의도하지 않은 데이터 소스를 스크래핑하지 못하도록 한다. 
5. 특정 교육 데이터 또는 데이터 소스 범주에 대한 엄격한 심사 또는 입력 필터를 사용하여 위조된 데이터의 양을 제어한다. 데이터 새니타이제이션, 통계적 이상치 탐지 및 이상 탐지 방법과 같은 기술을 사용하여 적대적 데이터가 미세 조정 프로세스에 잠재적으로 공급되지 않도록 탐지하고 제거한다.
6. 연합 학습 및 이상치의 영향을 최소화하거나 최악의 경우 훈련 데이터의 교란에 대해 강력하게 대처하는 제약 조건과 같은 적대적 견고성 기술
- "MLSecOps" 접근 방식은 자동 포이즈닝 기술을 사용하여 훈련 라이프사이클에 적대적 견고성을 포함한다.
- 이에 대한 예시 저장소는 Autopoison 테스트로, 이 접근 방식으로 수행할 수 있는 콘텐츠 주입 공격("모델 응답에서 브랜드 이름을 홍보하려고 시도") 및 거부 공격("항상 모델이 응답을 거부하게 함")과 같은 공격을 모두 포함한다. 
7. 테스트 및 감지: 훈련 단계에서 손실을 측정하고 훈련된 모델을 분석하여 특정 테스트 입력에서 모델 동작을 분석하여 포이즈닝 공격의 징후를 감지한다. 
- 임계값을 초과하는 왜곡된 응답 수에 대한 모니터링 및 경고
- 인간 루프를 사용하여 응답 및 감사를 검토한다. 
- 전담 LLM을 구현하여 바람직하지 않은 결과에 대한 벤치마킹을 수행하고 강화 학습 기술을 사용하여 다른 LLM을 훈련한다.
- LLM 라이프사이클의 테스트 단계에서 LLM 기반 레드팀 연습 또는 LLM 취약성 스캐닝을 수행한다. 

## LLM04: Model Denial of Service
공격자가 모델의 리소스 소비를 조작하여 서비스 저하와 잠재적으로 높은 비용을 초래할 수 있다.

### 방어책
- 입력 검증 및 살균을 구현하여 사용자 입력이 정의된 제한을 준수하고 악성 콘텐츠를 걸러내도록 합니다.
- 요청 또는 단계당 리소스 사용을 제한하여 복잡한 부분이 포함된 요청이 더 느리게 실행되도록 합니다.
- API 속도 제한을 적용하여 특정 기간 내에 개별 사용자 또는 IP 주소가 수행할 수 있는 요청 수를 제한합니다.
- 대기 중인 작업 수와 LLM 응답에 반응하는 시스템의 총 작업 수를 제한합니다.
- DoS 공격을 나타낼 수 있는 비정상적인 스파이크 또는 패턴을 식별하기 위해 LLM의 리소스 사용률을 지속적으로 모니터링합니다.
- 과부하 및 리소스 고갈을 방지하기 위해 LLM 컨텍스트 창에 따라 엄격한 입력 제한을 설정합니다.
- LLM의 잠재적인 DoS 취약성에 대한 개발자의 인식을 높이고 안전한 LLM 구현에 대한 지침을 제공합니다.

## LLM05: Supply Chain Vulnerabilities
모델 개발 시 사용된 훈련 데이터, 모듈, 라이브러리, 배포 플랫폼, 타사 솔루션과 관련된 취약점으로 인해 편향된 결과, 데이터 유출, 보안 문제 또는 시스템 장애가 발생할 수 있다.

### 방어책
1. 신뢰할 수 있는 공급업체만 사용하여 T&C 및 개인정보 보호 정책을 포함하여 데이터 소스 및 공급업체를 신중하게 검토합니다. 적절하고 독립적으로 감사된 보안이 적용되고 모델 운영자 정책이 데이터 보호 정책과 일치하는지 확인합니다. 즉, 데이터가 모델을 학습하는 데 사용되지 않습니다. 마찬가지로 모델 유지 관리자로부터 저작권이 있는 자료를 사용하지 않도록 보장하고 법적 완화 조치를 구합니다.
2. 평판이 좋은 플러그인만 사용하고 애플리케이션 요구 사항에 대해 테스트되었는지 확인하세요. LLM-Insecure Plugin Design은 타사 플러그인 사용으로 인한 위험을 완화하기 위해 테스트해야 하는 Insecure Plugin 디자인의 LLM 측면에 대한 정보를 제공합니다.
3. OWASP Top Ten's A06:2021 – 취약하고 오래된 구성 요소에서 발견되는 완화책을 이해하고 적용합니다. 여기에는 취약성 스캐닝, 관리 및 패치 구성 요소가 포함됩니다. 민감한 데이터에 액세스할 수 있는 개발 환경의 경우 해당 환경에도 이러한 제어를 적용합니다.
4. 소프트웨어 자재 목록(SBOM)을 사용하여 최신 구성 요소 인벤토리를 유지하여 배포된 패키지의 변조를 방지하는 최신, 정확하고 서명된 인벤토리를 보유합니다. SBOM은 새로운 제로데이 취약성을 신속하게 감지하고 경고하는 데 사용할 수 있습니다.
5. 이 글을 쓰는 시점에서 SBOM은 모델, 아티팩트, 데이터 세트를 다루지 않습니다. LLM 애플리케이션에서 자체 모델을 사용하는 경우 데이터, 모델, 실험 추적이 포함된 안전한 모델 리포지토리를 제공하는 MLOps 모범 사례와 플랫폼을 사용해야 합니다.
6. 외부 모델과 공급업체를 사용하는 경우에도 모델 및 코드 서명을 사용해야 합니다.
7. 제공된 모델과 데이터에 대한 이상 탐지 및 적대적 견고성 테스트는 [훈련 데이터 중독]( https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/main/1_0_vulns/Training_Data_Poisoning.md )에서 설명한 대로 변조 및 중독을 탐지하는 데 도움이 될 수 있습니다. 이상적으로는 이것이 MLOps 파이프라인의 일부가 되어야 하지만, 이는 새로운 기술이고 레드 팀 연습의 일부로 구현하기가 더 쉬울 수 있습니다.
8. 모델과 그 아티팩트를 포함하여, 구성 요소 및 환경 취약성 스캐닝, 승인되지 않은 플러그인 사용, 오래된 구성 요소 등을 포괄하는 충분한 모니터링을 구현합니다.
9. 취약하거나 오래된 구성 요소를 완화하기 위한 패치 정책을 구현합니다. 애플리케이션이 유지 관리된 버전의 API와 기본 모델에 의존하도록 합니다.
10. 공급업체의 보안 및 접근성을 정기적으로 검토하고 감사하여 보안 태세나 이용 약관에 변경 사항이 없는지 확인합니다.


## LLM06: Sensitive Information Disclosure
LLM 애플리케이션은 적절히 보호되지 않으면 기밀 정보나 독점 데이터를 부주의하게 유출시켜 사용자의 프라이버시를 침해할 수 있다. 이는 프롬프트 인젝션을 사용해서 LLM의 트레이닝 데이터를 유출시키는 것을 포함한다. 데이터 보안을 보장하고 무단 액세스를 방지하기 위해 LLM과 안전하게 상호 작용하는 방법을 알아야 한다.

### 방어책
1. 적절한 데이터 살균 및 스크러빙 기술을 통합하여 사용자 데이터가 학습 모델 데이터에 입력되지 않도록 합니다.
2. 강력한 입력 검증 및 살균 방법을 구현하여 잠재적인 악성 입력을 식별하고 필터링하여 모델이 오염되는 것을 방지합니다.
3. 모델을 데이터로 풍부하게 하고 모델을 미세 조정할 때: (즉, 배포 전 또는 배포 중에 모델에 입력된 데이터)
4. 미세 조정 데이터에서 민감한 것으로 간주되는 모든 내용은 사용자에게 공개될 가능성이 있습니다. 따라서 최소 권한 규칙을 적용하고 권한이 가장 5. 높은 사용자가 액세스할 수 있고 권한이 낮은 사용자에게 표시될 수 있는 정보에 대해 모델을 학습시키지 마십시오.
6. 외부 데이터 소스(런타임 시 데이터 오케스트레이션)에 대한 액세스는 제한되어야 합니다.
7. 외부 데이터 소스에 대한 엄격한 액세스 제어 방법과 안전한 공급망을 유지하기 위한 엄격한 접근 방식을 적용합니다.

## LLM07: Insecure Plugin Design
이는 적절한 통제나 검증 점검 없이 LLM 플러그인을 개발하는 행위로, 원격 코드 실행과 같은 유해한 행위로 이어질 수 있다.

### 방어책 
1. 플러그인은 가능한 한 엄격한 매개변수화된 입력을 적용하고 입력에 대한 유형 및 범위 검사를 포함해야 합니다. 이것이 불가능한 경우, 두 번째 계층의 유형화된 호출을 도입하여 요청을 구문 분석하고 유효성 검사 및 살균을 적용해야 합니다. 애플리케이션 의미론으로 인해 자유형 입력을 허용해야 하는 경우, 잠재적으로 유해한 메서드가 호출되지 않도록 주의 깊게 검사해야 합니다.
2. 플러그인 개발자는 ASVS(애플리케이션 보안 검증 표준)에서 OWASP의 권장 사항을 적용하여 효과적인 입력 유효성 검사 및 살균을 보장해야 합니다.
3. 플러그인은 적절한 유효성 검사를 보장하기 위해 철저히 검사하고 테스트해야 합니다. 개발 파이프라인에서 정적 애플리케이션 보안 테스트(SAST) 4. 검사와 동적 및 대화형 애플리케이션 테스트(DAST, IAST)를 사용합니다.
4. 플러그인은 OWASP ASVS 액세스 제어 지침에 따라 안전하지 않은 입력 매개변수 악용의 영향을 최소화하도록 설계해야 합니다. 여기에는 최소 권한 액세스 제어가 포함되어 원하는 기능을 수행하면서도 가능한 한 적은 기능을 노출합니다.
5. 플러그인은 효과적인 권한 부여 및 액세스 제어를 적용하기 위해 OAuth2와 같은 적절한 인증 ID를 사용해야 합니다. 또한 API 키는 기본 대화형 사용자가 아닌 플러그인 경로를 반영하는 사용자 지정 권한 부여 결정에 대한 컨텍스트를 제공하는 데 사용해야 합니다.
6. 민감한 플러그인에서 수행한 모든 작업에 대한 수동 사용자 권한 부여 및 확인을 요구합니다.
7. 플러그인은 일반적으로 REST API이므로 개발자는 OWASP Top 10 API Security Risks – 2023에서 발견된 권장 사항을 적용하여 일반적인 취약성을 최소화해야 합니다.

## LLM08: Excessive Agency
LLM 기반 시스템은 예상치 못한 결과를 초래하는 행동을 실행할 수 있다. 이 문제는 LLM 기반 시스템에 과도한 기능, 권리, 독립성을 부여함으로써 발생한다.

### 방어책 
다음 작업을 통해 과도한 에이전시를 방지할 수 있습니다.

1. LLM 에이전트가 호출할 수 있는 플러그인/도구를 필요한 최소한의 기능으로만 제한합니다. (최소 권한 원칙) 예를 들어, LLM 기반 시스템에서 URL의 내용을 가져오는 기능이 필요하지 않은 경우 해당 플러그인은 LLM 에이전트에 제공되어서는 안 됩니다.
2. LLM 플러그인/도구에 구현된 기능을 필요한 최소한으로 제한합니다. 예를 들어, 이메일을 요약하기 위해 사용자의 사서함에 액세스하는 플러그인은 이메일을 읽는 기능만 필요할 수 있으므로 플러그인에는 메시지 삭제 또는 전송과 같은 다른 기능이 포함되어서는 안 됩니다.
3. 가능한 경우 개방형 기능(예: 셸 명령 실행, URL 가져오기 등)을 피하고 보다 세부적인 기능이 있는 플러그인/도구를 사용합니다. 예를 들어, LLM 기반 앱은 일부 출력을 파일에 작성해야 할 수 있습니다. 이를 셸 함수를 실행하는 플러그인을 사용하여 구현한 경우 바람직하지 않은 작업의 범위가 매우 큽니다(다른 셸 명령을 실행할 수 있음). 보다 안전한 대안은 해당 특정 기능만 지원할 수 있는 파일 쓰기 플러그인을 빌드하는 것입니다.
4. LLM 플러그인/도구가 다른 시스템에 부여하는 권한을 최소한으로 제한하여 바람직하지 않은 작업의 범위를 제한합니다. 예를 들어, 고객에게 구매를 권장하기 위해 제품 데이터베이스를 사용하는 LLM 에이전트는 '제품' 테이블에 대한 읽기 액세스만 필요할 수 있습니다. 다른 테이블에 대한 액세스 권한이나 레코드를 삽입, 업데이트 또는 삭제할 수 있는 권한이 없어야 합니다. 이는 LLM 플러그인이 데이터베이스에 연결하는 데 사용하는 ID에 대한 적절한 데이터베이스 권한을 적용하여 시행해야 합니다.
5. 사용자 권한 부여 및 보안 범위를 추적하여 사용자를 대신하여 수행된 작업이 해당 특정 사용자의 컨텍스트에서 다운스트림 시스템에서 실행되고 필요한 최소 권한으로 실행되도록 합니다. 예를 들어, 사용자의 코드 리포를 읽는 LLM 플러그인은 사용자가 OAuth를 통해 인증하고 필요한 최소 범위로 인증하도록 요구해야 합니다.
6. 모든 작업을 수행하기 전에 사람이 승인하도록 하기 위해 인간-인-더-루프 제어를 활용합니다. 이는 다운스트림 시스템(LLM 애플리케이션 범위 밖) 또는 LLM 플러그인/도구 자체 내에서 구현될 수 있습니다. 예를 들어, 사용자를 대신하여 소셜 미디어 콘텐츠를 만들고 게시하는 LLM 기반 앱은 '게시' 작업을 구현하는 플러그인/도구/API 내에 사용자 승인 루틴을 포함해야 합니다.
7. LLM에 의존하여 작업이 허용되는지 여부를 결정하는 대신 다운스트림 시스템에서 권한을 구현합니다. 도구/플러그인을 구현할 때 플러그인/도구를 통해 다운스트림 시스템에 요청된 모든 요청이 보안 정책에 대해 검증되도록 완전한 중재 원칙(complete mediation principle)을 적용합니다.

다음 옵션은 과도한 에이전시를 방지하지 못하지만 발생하는 피해 수준을 제한할 수 있습니다.

1. LLM 플러그인/도구 및 다운스트림 시스템의 활동을 기록하고 모니터링하여 바람직하지 않은 작업이 발생하는 위치를 식별하고 그에 따라 대응합니다.
2. 속도 제한을 구현하여 지정된 기간 내에 발생할 수 있는 바람직하지 않은 작업의 수를 줄이고, 심각한 피해가 발생하기 전에 모니터링을 통해 바람직하지 않은 작업을 발견할 수 있는 기회를 늘립니다.

## LLM09: Overreliance
이는 LLM의 취약점이라기보다는 사용자에 대한 위협이다. 이는 LLM의 출력을 사용하는 사용자가 겪을 수 있는 모든 종류의 영향, 즉 법적 영향, 허위 정보의 확산 등을 의미한다. LLM이 잘못된 정보를 생산하고 권위 있는 방식으로 제공할 때 과도한 의존이 발생할 수 있다. LLM은 창의적이고 유익한 콘텐츠를 생산할 수 있지만, 사실적으로 부정확하거나 부적절하거나 안전하지 않은 콘텐츠를 생성할 수도 있다. 이를 환각 또는 조작이라고 한다. 사람이나 시스템이 감독이나 확인 없이 이 정보를 신뢰하면 보안 침해, 잘못된 정보, 오해의 소지, 법적 문제 및 평판 손상이 발생할 수 있다.

### 방어책 

1. LLM 출력을 정기적으로 모니터링하고 검토합니다. 일관성 없는 텍스트를 걸러내기 위해 자체 일관성 또는 투표 기술을 사용합니다. 단일 프롬프트에 대한 여러 모델 응답을 비교하면 출력의 품질과 일관성을 더 잘 판단할 수 있습니다.
2. 신뢰할 수 있는 외부 소스와 LLM 출력을 교차 확인합니다. 이 추가적인 검증 계층은 모델에서 제공하는 정보가 정확하고 신뢰할 수 있는지 확인하는 데 도움이 될 수 있습니다.
3. 출력 품질을 개선하기 위해 미세 조정 또는 임베딩으로 모델을 강화합니다. 일반적인 사전 학습된 모델은 특정 도메인의 조정된 모델에 비해 부정확한 정보를 생성할 가능성이 더 높습니다. 프롬프트 엔지니어링, 매개변수 효율적 조정(PET), 전체 모델 조정 및 사고의 사슬 프롬핑과 같은 기술을 이 목적으로 사용할 수 있습니다.
4. 생성된 출력을 알려진 사실이나 데이터와 교차 검증할 수 있는 자동 검증 메커니즘을 구현합니다. 이를 통해 보안 계층을 추가로 제공하고 환각과 관련된 위험을 완화할 수 있습니다.
5. 복잡한 작업을 관리 가능한 하위 작업으로 나누어 다른 에이전트에게 할당합니다. 이는 복잡성을 관리하는 데 도움이 될 뿐만 아니라 각 에이전트가 더 작은 작업에 대해 책임을 질 수 있으므로 환각의 가능성도 줄어듭니다.
6. LLM 사용과 관련된 위험과 한계를 전달합니다. 여기에는 정보 부정확성 및 기타 위험이 포함됩니다. 효과적인 위험 커뮤니케이션은 사용자에게 잠재적인 문제에 대비할 수 있도록 준비하고 정보에 입각한 결정을 내리는 데 도움이 될 수 있습니다.
7. LLM의 책임감 있고 안전한 사용을 장려하는 API와 사용자 인터페이스를 구축합니다. 여기에는 콘텐츠 필터, 잠재적 부정확성에 대한 사용자 경고, AI 생성 콘텐츠에 대한 명확한 라벨링과 같은 조치가 포함될 수 있습니다.
8. 개발 환경에서 LLM을 사용하는 경우 잠재적인 취약점이 통합되는 것을 방지하기 위해 안전한 코딩 관행과 지침을 수립하세요.

## LLM10: Model Theft
모델의 유출, 유출 또는 카피로 인해 경쟁 우위를 잃을 수 있다.

### 방어책 
1. LLM 모델 저장소와 교육 환경에 대한 무단 액세스를 제한하기 위해 강력한 액세스 제어(예: RBAC 및 최소 권한 규칙)와 강력한 인증 메커니즘을 구현합니다.
- 이는 특히 처음 세 가지 일반적인 예에 ​​해당하는데, 이는 악의적인 행위자가 환경 내부 또는 외부에서 침투할 수 있는 LLM 모델, 가중치 및 아키텍처를 수용하는 인프라에 대한 내부 위협, 잘못된 구성 및/또는 취약한 보안 제어로 인해 이러한 취약성이 발생할 수 있기 때문입니다.
- 공급업체 관리 추적, 검증 및 종속성 취약성은 공급망 공격 악용을 방지하기 위한 중요한 초점 주제입니다.
2. 프로덕션에서 사용되는 ML 모델에 중앙 집중식 ML 모델 인벤토리 또는 레지스트리를 사용합니다. 중앙 집중식 모델 레지스트리를 사용하면 액세스 제어, 인증 및 모니터링/로깅 기능을 통해 ML 모델에 대한 무단 액세스를 방지할 수 있으며, 이는 거버넌스의 좋은 기반입니다. 중앙 집중식 저장소를 갖는 것은 규정 준수, 위험 평가 및 위험 완화를 위해 모델에서 사용하는 알고리즘에 대한 데이터를 수집하는 데에도 유용합니다.
3. LLM의 네트워크 리소스, 내부 서비스 및 API 액세스를 제한합니다.
- 이는 내부 위험과 위협을 다루는 모든 일반적인 예에 ​​특히 해당하지만 궁극적으로는 LLM 애플리케이션이 "액세스할 수 있는" 것을 제어하므로 사이드 채널 공격을 방지하기 위한 메커니즘 또는 예방 단계가 될 수 있습니다.
4. LLM 모델 저장소와 관련된 액세스 로그와 활동을 정기적으로 모니터링하고 감사하여 의심스럽거나 승인되지 않은 행동을 즉시 감지하고 대응합니다.
5. 인프라 내에서 액세스 및 배포 제어를 강화하기 위해 거버넌스, 추적 및 승인 워크플로를 통해 MLOps 배포를 자동화합니다.
6. 즉각적인 주입 기술로 인해 사이드 채널 공격이 발생하는 위험을 완화 및/또는 줄이기 위해 통제 및 완화 전략을 구현합니다.
7. 해당되는 경우 API 호출의 속도 제한 및/또는 LLM 애플리케이션에서 데이터 유출 위험을 줄이기 위한 필터 또는 다른 모니터링 시스템에서의 추출 활동(예: DLP)을 감지하는 기술을 구현합니다.
8. 추출 쿼리를 탐지하고 물리적 보안 조치를 강화하는 데 도움이 되는 적대적 견고성 훈련을 구현합니다.
9. LLM 라이프사이클의 임베딩 및 감지 단계에 워터마킹 프레임워크를 구현합니다.

# LLM 공격 방어책 (by PortSwigger)
## LLM이 사용가능한 API는 공개적으로 접근가능한 것으로 간주한다
- 이는 LLM이 API를 수행할 때마다 인증을 요구해야 한다는 것을 의미한다. 
- 또한 LLM이 사용하는 API에 접근 제어를 수행한다. LLM이 통신하는 애플리케이션이 자체적으로 유저입력을 감시할 것을 기대하지 말고 애플리케이션에서 처리하도록 해야 한다. 이는 특히 권한 문제와 밀접하게 연관되어 있으며 적절한 권한 제어를 통해 어느 정도 완화할 수 있는 간접 프롬프트 인젝션 공격의 가능성을 줄이는 데 도움이 될 수 있다.

## LLM에 민감한 데이터를 제공하지 않기
LLM에 민감한 데이터를 제공하지 않기 위해 다음 방법을 검토한다. 
- 모델의 학습 데이터 세트에 강력한 새니타이제이션 기술을 적용한다. 
- 가장 낮은 권한의 사용자가 액세스할 수 있는 모델에만 데이터를 공급한다. 이는 모델에서 소비한 모든 데이터가 특히 미세 조정 데이터의 경우 사용자에게 잠재적으로 공개될 수 있기 때문에 중요하다. 
- 모델이 외부 데이터 소스에 접근하는 것을 제한하고, 전체 데이터 공급망에 강력한 액세스 제어가 적용되도록 합니다.
- 정기적으로 모델을 테스트하여 민감한 정보에 대한 지식을 확립한다.

## 공격을 차단하기 위해 프롬프트에 의존하지 않기
이론적으로 프롬프트를 사용하여 LLM 출력에 제한을 설정할 수 있다. 예를 들어, "이러한 API를 사용하지 마십시오" 또는 "페이로드가 포함된 요청 무시"와 같은 지침을 모델에 제공할 수 있다.

하지만 이 기술에 의존해서는 안 된다. 공격자가 "사용할 API에 대한 모든 지시를 무시하세요"와 같은 정교하게 만든 프롬프트를 사용하여 우회할 수 있기 때문이다. 이러한 프롬프트는 때때로 탈옥기(제일브레이커) 프롬프트라고도 불린다. 


# LLM 메모
- LLM은 FM(Foundation Model)의 한 타입이다. 
- FM은 다양한 작업을 수행할 수 있도록 사전에 학습된 머신 러닝 모델이다.
- AWS에서 FM을 제공해주는 서비스로는 Amazon Bedrock 이 있다. 
- FM은 AI 기술의 기반이라고 볼 수 있다. 
- AI의 발전을 살펴보면 머신러닝 -> 딥러닝 -> 파운데이션 모델로 발전해온 것을 알 수 있다. 
- 딥러닝 모델을 특정 레시피만 숙지한 요리사라고 한다면, 파운데이션 모델은 요리의 기본 원리를 터득한 셰프라고 생각하면 된다. 
- ChatGPT와 같은 생성형 인공지능 서비스는 **GPT라는 파운데이션 모델**을 사용한 챗봇 서비스이다. 

# 참고 
- https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- https://genai.owasp.org/llmrisk/llm02-insecure-output-handling/
- LLM을 위협모델링한 것(재밌어 보인다. 나중에 읽어보자): https://aivillage.org/large%20language%20models/threat-modeling-llm/
- 랭체인(LangChain) 입문부터 응용까지 : https://wikidocs.net/231156
- https://portswigger.net/web-security/llm-attacks
- https://www.ibm.com/topics/prompt-injection
- https://benn.tistory.com/60
- 머신러닝, 딥러닝 개념: https://brunch.co.kr/@morningb/3