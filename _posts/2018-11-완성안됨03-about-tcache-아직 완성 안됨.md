---
layout: po123st
title: ubuntu 18.04 tcache (번역)
author: hOwDayS
---



출처 : http://tukan.farm/2017/07/08/tcache/



<h1>TLDR</h1>

- per-thread caching 로 바뀐점
- 예전 기법에 어떤 영향을 미치는 지
  - House of Spirit , Overlapping Chunks : 전(16.04) 보다 쉬운 조건으로 익스플로잇 가능
  - tcache poisoning : fastbin 과 비슷하게 다음에 할당 될 chunk의 주소를 조작하여 arbitary write 가능
- 새롭게 생긴점



<h1>Overview</h1>

<h3>New structures</h3>

새롭게 tcache 구조체  [tcache_entry](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=2527e2504761744df2bdb1abdc02d936ff907ad2;hb=d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc#l2927) 와 [tcache_perthread_struct](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=2527e2504761744df2bdb1abdc02d936ff907ad2;hb=d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc#l2937)  가 생겻다.

기본적으로 하나의 tcache 에는 최대 7개의 bin이 들어갈 수 있다.



```c++
/* We overlay this structure on the user-data portion of a chunk when the chunk is stored in the per-thread cache.  */
typedef struct tcache_entry
{
  struct tcache_entry *next;
} tcache_entry;

/* There is one of these for each thread, which contains the per-thread cache (hence "tcache_perthread_struct").  Keeping overall size low is mildly important.  Note that COUNTS and ENTRIES are redundant (we could have just counted the linked list each time), this is for performance reasons.  */
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;

static __thread tcache_perthread_struct *tcache = NULL;
```



<h3>tcache usage</h3>

- free : 전의 fastbin의 \_int\_free에는 , free하려는 chunk 의 size가 