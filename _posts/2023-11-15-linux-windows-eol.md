---
layout: post
title: "셸 스크립트가 윈도우즈에서 실행이 안 될 때(리눅스, 윈도우즈 사이의 EOL문자 차이에 대해서)"
categories: [보안일반]
tags: [보안일반]
toc: true
last_modified_at: 2023-11-15 09:50:00 +0900
---

# 개요
- 리눅스용으로 만들어진 셸 스크립트를 윈도우즈의 Cygwin 등 리눅스 에뮬레이터를 통해서 실행할 필요가 있을 때가 있다. 
- 이 때, 특히 셸 스크립트가 결과물로서 어떤 파일을 만들어내는 녀석일 경우, Cygwin에서 실행한 결과물이 제대로된 것이 아닌 경우가 있다. (결과물 파일을 윈도우즈에서 열어보면 개행이 이상한 곳에 들어가 있거나 한다. )
- 이는 주로 리눅스, 윈도우즈 사이의 EOL(End Of Line)문자 (혹은 개행문자) 차이가 원인이다. 
- 두 시스템 사이에 EOL은 어떻게 다른지, 어떻게 대처할 수 있는 지를 정리한다. 

# EOL문자에 대해 
- 종이를 한 줄 간격만큼 위로 올려주는 행위을 `LF(Line Feed)`라고 하고, 종이를 오른쪽 끝으로 보내주는 행위를 `CR(Carriage Return)`이라고 한다. 
- 과거 타자기를 제어하는 시절에는 작성하고 있는 문서를 한줄 내려서 작업 하기 위해 `CR(커서를 맨앞으로 되돌리기)`이후 `LF(종이를 한칸 올리기)`를 해야 했다. 
- 즉 한 줄을 내리기 위해서는 `CRLF`을 해야 했다. 
- 프로그램 코드로 표현할 때는 `\r`이 `CR`을, `\n`이 `LF`를 의미한다. 
- `CR`은 바이트로 표현하면 `0x0D`(아스키코드 13)이고, `LF`는 바이트로 `0x0A`(아스키코드 10)다. 
- 리눅스에서는 개행문자가 `LF`이고 윈도우즈에서는 개행문자가 `CRLF`이다. 
- 그리고 Cygwin등은 Linux셸 에뮬레이터지만 실행환경인 Windows의 EOL을 따라간다고 볼 수 있다. 

# 대처법
- 결과물이 Linux용이라면 Linux용의 EOF로 변환해주어야 한다. 

## Notepad++를 사용한 방법
- Notepad++를 사용하면 편리하게 변환할 수 있다. 
- [여기](https://notepad-plus-plus.org/downloads/)에서 다운로드받아서 설치한다. 
- 결과물을 Notepad로 읽어들인 후 Edit > EOL Conversion > Unix를 선택하면 된다. 
- 변환한 후에 파일을 저장하고, Cygwin 에서 다시 셸스크립트를 실행해보면 잘 동작할 것이다. 

![EOL Conversion](/images/notepad-plus-plus-eol-conversion.png)

# 참고 
- https://www.howtogeek.com/261591/how-to-create-and-run-bash-shell-scripts-on-windows-10/
- https://stackoverflow.com/questions/1552749/difference-between-cr-lf-lf-and-cr-line-break-types
- https://jw910911.tistory.com/90
- https://notepad-plus-plus.org/downloads/