---
layout: post
title: "Bootstrap 모달창 띄우기"
categories: [프로그래밍]
tags: [프로그래밍, 프론트엔드, bootstrap, modal]
toc: true
---

# 개요
- bootstrap 의 모달(modal)창을 띄우는 방법을 정리한다. 
- [공식문서](https://getbootstrap.com/docs/4.0/components/modal/){:target="_blank"} 를 참고했다. 

# 코드 분석 
- 공식문서의 샘플 코드를 분석해 본다. 

## 버튼 객체 
- 버튼(`<button>`)과 모달창을 나타내는 `<div>` 가 있다. 
- 버튼의 data-toggle 속성이 modal 로 되어 있다.
- modal 속성이 있어서 버튼을 누르면 모달이 나타나거나 사라지거나 하는 제어를 해주는 것으로 보인다. 
- 버튼 data-target 속성은 모달 div의 id를 가리키고 있다. 

```html
<!-- Button trigger modal -->
<button type="button" class="btn btn-primary" data-toggle="modal" data-target="#exampleModal">
  Launch demo modal
</button>
```

## 모달 객체 
- `<div class="modal body">` 부분에 컨텐츠를 넣으면 되겠다. 

```html
<!-- Modal -->
<div class="modal fade" id="exampleModal" tabindex="-1" role="dialog" aria-labelledby="exampleModalLabel" aria-hidden="true">
  <div class="modal-dialog" role="document">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="exampleModalLabel">Modal title</h5>
        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
          <span aria-hidden="true">&times;</span>
        </button>
      </div>
      <div class="modal-body">
        ...
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
        <button type="button" class="btn btn-primary">Save changes</button>
      </div>
    </div>
  </div>
</div>
```

# 트러블슈팅
## 모달창이 나타나지 않는 경우 
모달창이 나타나지 않는 경우 혹은 자바스크립트로 모달창을 호출했는데 콘솔에 다음과 같은 에러가 출력되는 경우가 있다.  
![javascript 모달창 에러](/images/bootstrap-modal-errer.png)

- 부트스트랩이 사용하는 자바스크립트가 제대로 로드되지 않은 것이 원인이다.   
- 내 경우에는 **웹 페이지에 부트스트랩용 자바스크립트 라이브러리(bootstrap.js)를 포함하는 부분이 없던 것**이 원인이었다.  
- 다음과 같이 웹 페이지 상단에 자바스크립트 라이브러리를 포함해주니 해결되었다. 
- 이 링크는 시간이 지남에 따라 변할 수 있다. 2022년 12월 26일 기준으로는 최신이다.
- [이 링크](https://getbootstrap.com/docs/4.4/getting-started/introduction/)에서 링크를 참고했다. 

```html 
<script src="https://code.jquery.com/jquery-3.4.1.slim.min.js" integrity="sha384-J6qa4849blE2+poT4WnyKhv5vZF5SrPo0iEjwBvKU7imGFAV0wwj1yYfoRSJoZ+n" crossorigin="anonymous"></script>
<script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.0/dist/umd/popper.min.js" integrity="sha384-Q6E9RHvbIyZFJoft+2mJbHaEWldlvI9IOYy5n3zV9zzTtmI3UksdQRVvoxMfooAo" crossorigin="anonymous"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.4.1/dist/js/bootstrap.min.js" integrity="sha384-wfSDF2E50Y2D1uUdj0O3uMBJnjuUD4Ih7YwaYd1iqfktj0Uod8GCExl3Og8ifwB6" crossorigin="anonymous"></script> 
```