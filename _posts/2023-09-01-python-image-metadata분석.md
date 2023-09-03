
# 개요
- 디지털 포렌식관련
- 파이썬에서 이미지 파일을 조사하기 위해 사용할 수 있는 라이브러리를 조사한다. 
- 라이브러리의 간단한 사용방법을 정리해둔다. 

# 라이브러리 조사 
## PIL
- 2011년까지는 파이썬의 메인 이미지 처리 라이브러리였던 것 같다. 
- 2011년 이후로는 개발되지 않고 있다. 

## Pillow
- PIL을 fork해서 개발되고 있는 라이브러리이다. 
- 요새 이미지 처리쪽에서 대세는 이 라이브러리인 것 같다. 
- PIL에 파이썬3 서포트 기능을 추가했다고 한다. 

```
pip install pillow
```

# 샘플이미지 
[여기](https://github.com/ianare/exif-samples)에서 메타 데이터가 포함된 샘플 이미지 파일을 얻을 수 있다. 

# 샘플코드

```py

```

## 실행결과 


# 메타데이터를 포함하는 이미지 형식 


# 삭제하는 방법

# 참고 
- https://en.wikipedia.org/wiki/Python_Imaging_Library
- https://dzone.com/articles/getting-gps-exif-data-with-python
- https://github.com/ianare/exif-samples
- https://stackoverflow.com/questions/72530975/extract-gps-data-using-python-and-pil-is-failing