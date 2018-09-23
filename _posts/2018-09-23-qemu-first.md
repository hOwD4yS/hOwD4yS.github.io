---
layout: post
title: gdb-multiarch 사용법 
author: hOwDayS
---



보통 우리가 쓰는 gdb 처럼 하면 안된다.

qemu-arm -g \[port] \[binary] 로 열어주고

$gdb-multiarch [binary]

$target remote localhost:port

<br>

pwntools에서는

```python
p = process(["qemu-arm","-g","port","binary"])
```

$gdb-multiarch [binary]

$target remote localhost:port

