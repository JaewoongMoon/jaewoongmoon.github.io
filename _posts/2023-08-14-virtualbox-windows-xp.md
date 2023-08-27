---
layout: post
title: "Virtualbox에 Windows XP 설치하기"
categories: [보안, Virtualbox, 취약한 환경구축]
tags: [보안, Virtualbox, 취약한 환경구축]
toc: true
last_modified_at: 2023-08-15 09:02:00 +0900
---

# 개요
- Virtualbox를 사용해서 Windows XP 를 구동하는 방법을 정리한다. 
- 취약점 연구가 목적이다. 
- Windows XP에는 다양한 취약점이 존재하고 있으므로 이 환경을 하나 구축해두면 두고두고 써먹을 수 있을 것이다. 
- Virtualbox는 7.0.0 r153978 (2022년 버전)을 사용했다. 


# ISO 구하기 
- https://archive.org/details/WinXPProSP3x86 에서 en_windows_xp_professional_with_service_pack_3_x86_cd_vl_x14-73974.iso를 다운로드 받는다. 여러 언어 버전이 있다. 영어버전을 다운로드 받았다. 

# 설치
1. Virtualbox에서 새로 만들기를 눌러서 다운로드 받은 ISO를 추가한다. 

![ISO파일을 통해 설치](/images/virtualbox-windows-xp-01.png)

2. 유저네임과 Host name등을 입력한다. Product Key는 나중에 입력해도 된다. (Product Key는 알아서 구해야 한다. 구매하던가..)

![기본정보입력](/images/virtualbox-windows-xp-02.png)

Hostname은 공백을 허용하지 않기 때문에 공백을 하이픈(-)등으로 바꿔준다. 

![Hostname변경](/images/virtualbox-windows-xp-03.png)

3. 메모리를 설정해준다. 1024MB로 설정해주었다. 

![메모리 설정](/images/virtualbox-windows-xp-04.png)

4. 하드디스크 크기를 설정해준다. 10기가바이트로 설정해주었다. 

![하드디스크 크기 설정](/images/virtualbox-windows-xp-05.png)

5. Finish를 눌러서 설정을 완료한다. 이후는 가만히 놔두면 알아서 설치가 된다. \

![설정완료](/images/virtualbox-windows-xp-06.png)

그리운 파란화면이 나타난다. 

![파란화면](/images/virtualbox-windows-xp-06-01.png)

자동으로 재부팅이 되고 설치가 진행되는데, 이 단계에서 갑자기 꺼져 버린다. 

![설정완료](/images/virtualbox-windows-xp-06-02.png)

조사해보니 최신의 오디오 디바이스를 Windows XP가 인식하지 못해서 생기는 에러라고 한다. Virtualbox에서 오디오 사용하기 체크를 해제하고 다시 부팅하니 설치가 진행되었다. 

![설정완료](/images/virtualbox-windows-xp-06-03.png)

6. 설치가 완료된 화면이다. 

![설치 완료](/images/virtualbox-windows-xp-07.png)

7. 커맨드 프롬프트(cmd)에서 열린 포트를 IP 설정을 확인해본다. 
- TCP 445포트나 139포트가 열려 있는 것을 알 수 있다. 
- 이 것으로 SMB프로토콜이 기본적으로 동작중인 것을 알 수 있다. 

![열린 포트 확인](/images/virtualbox-windows-xp-08.png)


# 네트워크 설정 
1. 호스트와 게스트OS간에 통신이 되도록 네트워크를 구성한다. XP를 종료한 상태에서 네트워크 설정으로 들어간다. 

2. 호스트 전용 어댑터를 추가한다. 어댑터 종류는 Pcnet-FAST III를 선택해준다. 기본값은 Intel PRO/1000 인데, Windows XP에는 이 카드용의 드라이버가 없으므로 Pcnet-FAST III를 선택해주어야만 호스트와 게스트 OS간에 통신이 된다. (출처: https://superuser.com/questions/892729/virtualbox-windows-xp-has-no-local-network)

![호스트 전용 어댑터 추가](/images/virtualbox-windows-xp-09.png)

3. 어댑터를 추가했으면 다시 XP를 구동하고 커맨드 프롬프트에서 IP정보를 확인해본다. 192.168.xxx.xxx 가 추가되었으면 제대로 설정이 된 것이다. 

![호스트 전용 어댑터 IP주소 확인](/images/virtualbox-windows-xp-10.png)

4. 그런데 게스트OS(XP)에서 호스트로는 ping이 가능한데, 호스트에서 게스트OS로는 ping이 불가능하다. 이 것은 XP에서 기본적으로 동작하고 있는 Windows Defender 방화벽 때문이다. 방화벽을 꺼주면 호스트에서 게스트로 ping을 보낼 수 있다. (출처: https://superuser.com/questions/1580547/virtualbox-host-only-network-cannot-ping-host-from-guest)

![Windows Defender끄기](/images/virtualbox-windows-xp-11.png)

이 것으로 기본적인 Windwos XP 설정을 마쳤다. 

# 스냅샷 
- 기본적인 설정을 마쳤으면 스냅샷을 하나 찍어두면 좋다. (추후 설정이 꼬였거나 했을 때 복구하는 용도로 쓴다.)
- Virtualbox에서 해당 이미지를 선택한 상태에서 붉은 박스의 아이콘을 클릭한 후 스냅샷을 선택한다. 
- 상단의 "찍기" 를 클릭해서 스냅샷을 찍을 수 있다. 

![스냅샷](/images/virtualbox-windows-xp-12.png)


# 기타 설정 방법 
## 파일공유 켜기 (simple file sharing)
Windows XP에서 파일 공유를 켜는 방법을 정리한다. 

1. 공유하고자 하는 폴더를 선택후 메뉴에서 Sharing and Security를 선택한다. 

![Just enable file sharing](/images/virtualbox-windows-xp-filesharing-01.png)

2. Network sharing and security에서 붉은 박스 부분을 선택한다. 

![Just enable file sharing](/images/virtualbox-windows-xp-filesharing-02.png)

3. Just enable file sharing을 선택한다. 

![Just enable file sharing](/images/virtualbox-windows-xp-enable-filesharing.png)

4. 공유할 폴더의 이름을 선택한다. 

![Just enable file sharing](/images/virtualbox-windows-xp-filesharing-03.png)

5. 공유가 완료된 모습이다. C드라이브 전체를 공유한 화면이다. 
![Just enable file sharing](/images/virtualbox-windows-xp-filesharing-04.png)

6. 파일공유가 제대로 되었는지 호스트 PC나 다른 게스트 OS에서 테스트해본다. Windows PC라면 탐색기 주소창에서 `\\IP주소\공유폴더명`으로 접근할 수 있다. 예를들면, `\\192.168.56.103\Documents` 같은 식이다. 



# 참고 
- https://www.youtube.com/watch?v=7NJupnHcxpE
- https://archive.org/details/WinXPProSP3x86
- https://superuser.com/questions/892729/virtualbox-windows-xp-has-no-local-network
- https://superuser.com/questions/1580547/virtualbox-host-only-network-cannot-ping-host-from-guest