

# 개요
- Virtualbox 에 Ubuntu를 설치하는 과정에서 생긴 트러블을 정리해둔다. 
- Virtualbox 버전: 7.0.20 (2024/07/17 기준 최신버전이다.)
- Ubuntu 버전: ubuntu-24.04-desktop-amd64.iso (2024/07/17 기준 최신버전이다.)


# 팁
## 메모리, CPU 설정
- 일단 메모리와 프로세서를 넉넉하게 주자. 안 그러면 너무 느리다. 
- 메모리는 4096 MB, 프로세서는 2개를 100%로 주었다. 

![](/images/virtualbox-ubuntu-processor.png)

## 게스트 확장 이미지 설치
1. 게스트 확장 이미지를 설치할 때 OS 모듈을 빌드할 필요가 있다. 따라서 다음 명령어를 먼저 실행해준다. 

```sh
sudo apt update
sudo apt -y upgrade
sudo apt -y install build-essential
```

2. 설치를 수행한다. 


3. 재부팅한다. 그러면 양방향 클립보드 공유, 창 크기에 맞춰서 해상도 변경등이 되는 것을 확인할 수 있다. 

다음을 참고하였다. 
- https://siloam72761.tistory.com/entry/Virtualbox-%EC%9A%B0%EB%B6%84%ED%88%AC-%ED%99%94%EB%A9%B4-%ED%81%AC%EA%B8%B0%EC%97%90-%EB%94%B0%EB%9D%BC-%EC%9E%90%EB%8F%99-%EC%A1%B0%EC%A0%88%ED%95%98%EA%B8%B0-%EC%97%AC%EB%9F%AC-%ED%95%B4%EA%B2%B0%EC%B1%85

# 트러블 슈팅
## 그래픽카드 설정
- 그래픽 카드설정이 잘못되면, 설치시에 검은화면에서 더 이상 넘어가지 않는다. 검색해보니 우분투 설치시에는 흔한 증상인 것 같다. 
- 내 경우에는 `VMSVGA`로 선택해주어야 잘 설치됐다.  

![](/images/virtualbox-ubuntu-graphic.png)


## 화면이 멈추는 문제
- 다음 블로그 글을 참고했다. 
- https://inpa.tistory.com/entry/LINUX-%F0%9F%93%9A-%EC%9A%B0%EB%B6%84%ED%88%AC-%ED%84%B0%EB%AF%B8%EB%84%90%ED%99%94%EB%A9%B4-%EB%A8%B9%ED%86%B5-%ED%98%84%EC%83%81-%ED%95%B4%EA%B2%B0-%EC%A0%95%EB%A6%AC


