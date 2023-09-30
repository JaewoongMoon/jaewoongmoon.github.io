---
layout: post
title: "파이썬으로 이미지 메타데이터 분석하기"
categories: [포렌식, 파이썬]
tags: [포렌식, 파이썬, 이미지, exif, 메타데이터]
toc: true
last_modified_at: 2023-09-04 16:15:00 +0900
---


# 개요
- 디지털 포렌식에서는 이미지를 분석할 때 교환 이미지 파일형식(Exchange Image File Format, exif)이라고 알려진 이미지의 메타데이터를 조사한다. 
- 파이썬을 사용해서 exif 메터데이터를 확인할 수 있는 라이브러리를 조사하고 간단한 사용방법을 정리해둔다. 
- 참고로 대부분의 이미지 파일 형식은 exif 를 포함할 수 있다고 한다. png파일 형식도 원래는 exif를 포함할 수 없었으나 2017년부터는 가능해졌다고 한다. (출처: https://stackoverflow.com/questions/9542359/does-png-contain-exif-data-like-jpg)
- 대부분의 SNS에 사진을 업로드하게 되면 exif데이터를 삭제된 상태로 업로드되게 된다. 

# 파이썬 라이브러리 조사 
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

## exif 
- exif 라는 메타데이터 만을 전문적으로 분석해주는 라이브러리도 있는 것 같다. 
- https://pypi.org/project/exif/

```
pip install exif 
```

# 샘플이미지 
[여기](https://github.com/ianare/exif-samples)에서 메타 데이터가 포함된 샘플 이미지 파일을 얻을 수 있다. 

# 샘플코드
## Pillow를 사용한 샘플코드
- 다음 코드를 사용해서 이미지 파일에 메타데이터, 특히 GPS 좌표가 들어가 있는지 확인할 수 있다. 
- 그러나 GPS의 구체적인 위치를 얻어내는 데에는 실패했다. 

```py
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS


def get_exif(image_file_path):
    exif_info = {}
    gps_info = {}
    imgFile = Image.open(image_file_path)
    info = imgFile.getexif()
    if info:
        for tag, value in info.items():
            decoded = TAGS.get(tag, tag)
            exif_info[decoded] = value
        print(exif_info)
        # GPS
        exif_gps = exif_info['GPSInfo']
        if exif_gps:
            print(f"[*] {image_file_path} contains GPS MetaData")
            for key in exif_info['GPSInfo'].keys():
                decoded = GPSTAGS.get(key, key)
                gps_info[decoded] = exif_info['GPSInfo'][key]            

        return exif_info, gps_info
    

if __name__ == '__main__':
    file_name = "20230725_183324.jpg"
    exif_info, gps_info = get_exif(file_name)
    print(exif_info)
    print(gps_info)
```

## exif를 사용한 샘플코드
- Pillow보다 exif를 사용한 샘플코드가 더 잘 동작했다. (출처: https://stackoverflow.com/questions/72530975/extract-gps-data-using-python-and-pil-is-failing)
- GPS의 구체적인 위치도 파악이 가능하다. 

```py
from exif import Image
from gmplot import gmplot
from geopy.geocoders import Nominatim
import webbrowser
import os

def decimal_coords(coords, ref):
    decimal_degrees = coords[0] + coords[1] / 60 + coords[2] / 3600
    if ref == 'S' or ref == 'W':
        decimal_degrees = -decimal_degrees
    return decimal_degrees

file_name = "20230725_183324"
input = f'{file_name}.jpg'
output = f'{file_name}-location.html'

with open(input, 'rb') as src:
    img = Image(src)

lat = decimal_coords(img.gps_latitude, img.gps_latitude_ref)
lon = decimal_coords(img.gps_longitude, img.gps_longitude_ref)

gmap = gmplot.GoogleMapPlotter(lat, lon, 12)
gmap.marker(lat, lon, 'red')
gmap.draw(output)

address = Nominatim(user_agent='GetLoc')
location = address.reverse(f'{lat}, {lon}')

print(location.address)

webbrowser.open(f'file:///{os.getcwd()}/{output}', new=1)
```

# exif정보를 삭제하는 방법
- 출처: https://stackoverflow.com/questions/19786301/python-remove-exif-info-from-images
- Pillow 라이브러리를 사용해서 다음 코드로 exif정보를 삭제한 이미지를 저장할 수 있다. 

```py
from PIL import Image

image = Image.open('image_file.jpeg')
    
# next 3 lines strip exif
data = list(image.getdata())
image_without_exif = Image.new(image.mode, image.size)
image_without_exif.putdata(data)
    
image_without_exif.save('image_file_without_exif.jpeg')

# as a good practice, close the file handler after saving the image.
image_without_exif.close()
```

- 또는 exif-delete(https://pypi.org/project/exif-delete/)와 같은 전용 라이브러리를 사용해도 좋을 것 같다. 

# 참고 
- https://en.wikipedia.org/wiki/Python_Imaging_Library
- https://dzone.com/articles/getting-gps-exif-data-with-python
- https://github.com/ianare/exif-samples
- https://stackoverflow.com/questions/72530975/extract-gps-data-using-python-and-pil-is-failing
- https://www.adobe.com/jp/creativecloud/file-types/image/raster/exif-file.html