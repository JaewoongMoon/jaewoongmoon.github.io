---
layout: post
title: "파이썬으로 벤다이어그램 그리기"
categories: [파이썬, 데이터분석, 데이터시각화]
tags: [파이썬, 데이터분석, 데이터시각화]
toc: true
last_modified_at: 2023-09-25 16:15:00 +0900
---

# 개요
파이썬에서 여러개의 데이터셋을 벤 다이어그램을 사용해서 표현하는 방법을 정리해둔다. 

# 설치
`matplotlib-venn` 라이브러리를 사용한다. 

```sh
pip install matplotlib-venn
```

# 라이브러리 임포트 

```py
import matplotlib.pyplot as plt
from matplotlib_venn import venn2
```

# 샘플 코드
- 두 개의 파이썬 셋을 만든다. 
- 다음 코드를 많이 쓴다. 

```py
import matplotlib.pyplot as plt
from matplotlib_venn import venn2
 
venn2([set(['A', 'B', 'C', 'D']), set(['D', 'E', 'F'])], set_labels=('Group A', 'Group B'))
plt.show()
```

실행하면 다음과 같은 그래프가 출력된다.   
위의 샘플에서 공통으로 가지고 있는 D의 숫자 1의 교집합부분에 표시되고, 각각의 그룹에서만 존재하는 아이템의 숫자가 표시된다. 

![벤 다이어그램 샘플](/images/python-venn-diagram-sample.png)


# 참고 
- https://python-graph-gallery.com/170-basic-venn-diagram-with-2-groups/
- 