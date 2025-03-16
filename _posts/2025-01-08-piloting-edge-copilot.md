

# 개요
엣지 코파일럿에 있는 취약점에 대한 보고가 있어서 내용을 정리해본다.

# Edge Copilot
- 엣지에 있는 사이드바다. 
- 현재 활성화되어 있는 탭에 접근할 수 있는 권한을 갖고 있다. 
- 많은 권한이 필요한 API가 노출되어 있고, Edge에 밀접하게 통합되어 있다. 

# 등장요소
1. edge://discover-chat Web UI
- 카메라와 마이크에 대한 접근권한을 기본으로 갖고 있다. 
- pviate/public 을 포함한 다양한 확장 API에 대한 접근권한을 갖고 있다. 

2. edge://discover-chat
- XSS에 대비해서 강력한 CSP를 갖고 있는 SPA (싱글 페이지 앱)
- 보안레벨 높다. 

3. edgeservices.bing.com 
- Strict CSP 
- Copilot UI가 호스팅되는 사이트다. 

4. www.bing.com
- 여기에는 postMessage로 트리거할 수 있는 XSS가 존재한다. 
- postMessage의 값을 iframe의 src에 삽입할 수 있다. 
- 보안레벨 낮다. 

# 시나리오/조건
1. www.bing.com 에 `chrome.edgeSplitTabsPrivate`, `chrome.edgeMarketingPagePrivate` 등 몇 가지 private API가 노출되어 있다. 
   - `chrome.edgeSplitTabsPrivate` 는 Edge내에서 탭을 분리할 수 있는 API이다. (팝업 블로커를 우회할 수 있는 것 같다.)
   

# Permission Delegation 
- top-level page에서 권한을 얻을 수 있다. 그리고 크로스오리진 iframe으로 권한이 delegate(위임)되어져 간다. 
- alllow 속성을 통해 허용할 수 있다. 


# Madding the last chain
- CSP Embedded Enforcement 는 모든 중첩된 iframe에게도 위임되어 진다. 

# 공격결과
- 공격자의 사이트에서 Edge Coplit sidebar 에 접근권한을 얻어냈다. 
- 데모: https://www.youtube.com/watch?v=7NydJCndmws

# 결론
- 비교적 안전한 시스템 Edge와 안전하지 않은 시스템 Bing이 결합하면 안전하지 않은 시스템이 된다. 
- AI 관련 리스크는 문제지만, 클래식 앱/브라우저 보안 문제는 더욱 큰 리스크다. 
- AI관련한 exfiltration 테크닉은 막기 힘들다. 

# 참고
- 슬라이드: https://speakerdeck.com/shhnjk/piloting-edge-copilot
- 데모: https://www.youtube.com/watch?v=7NydJCndmws