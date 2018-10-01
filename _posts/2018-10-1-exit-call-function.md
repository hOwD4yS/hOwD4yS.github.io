---
layout: post
title: exit함수를 파헤치고 exploit를 해보자! (glibc 2.25 기준)
author: hOwDayS
---

<br>

exit.c 

```c++
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sysdep.h>
#include "exit.h"

#include "set-hooks.h"
DEFINE_HOOK (__libc_atexit, (void))


void
attribute_hidden
__run_exit_handlers (int status, struct exit_function_list **listp,
		     bool run_list_atexit, bool run_dtors)
{
  /* First, call the TLS destructors.  */
#ifndef SHARED
  if (&__call_tls_dtors != NULL)
#endif
    if (run_dtors)
      __call_tls_dtors ();

  /* We do it this way to handle recursive calls to exit () made by
     the functions registered with `atexit' and `on_exit'. We call
     everyone on the list and use the status value in the last
     exit (). */
  while (*listp != NULL)
    {
      struct exit_function_list *cur = *listp;

      while (cur->idx > 0)
	{
	  const struct exit_function *const f =
	    &cur->fns[--cur->idx];
	  switch (f->flavor)
	    {
	      void (*atfct) (void);
	      void (*onfct) (int status, void *arg);
	      void (*cxafct) (void *arg, int status);

	    case ef_free:
	    case ef_us:
	      break;
	    case ef_on:
	      onfct = f->func.on.fn;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (onfct);
#endif
	      onfct (status, f->func.on.arg);
	      break;
	    case ef_at:
	      atfct = f->func.at;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (atfct);
#endif
	      atfct ();
	      break;
	    case ef_cxa:
	      cxafct = f->func.cxa.fn;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (cxafct);
#endif
	      cxafct (f->func.cxa.arg, status);
	      break;
	    }
	}

      *listp = cur->next;
      if (*listp != NULL)
	/* Don't free the last element in the chain, this is the statically
	   allocate element.  */
	free (cur);
    }

  if (run_list_atexit)
    RUN_HOOK (__libc_atexit, ());

  _exit (status); 
}


void
exit (int status)
{
  __run_exit_handlers (status, &__exit_funcs, true, true);
}
libc_hidden_def (exit)
```

<br>

exit함수는 exit.h 에서 정의된 __run_exit_handlers 를 호출합니다.

```c++
extern void __run_exit_handlers (int status,
				 struct exit_function_list **listp,
				 bool run_list_atexit, bool run_dtors)
  attribute_hidden __attribute__ ((__noreturn__));
```

```
 ► 0x7ffff7521040 <exit+16>       call   __run_exit_handlers <0x7ffff7520f10>
        rdi: 0xffffffff
        rsi: 0x7ffff78ab5f8 (__exit_funcs) —▸ 0x7ffff78acc40 (initial) ◂— 0x0
        rdx: 0x1
```

인자는 위 처럼 들어간다는 것을 알 수 있습니다.

<br>

exit_function_list 구조체는 이러합니다.

```c++
struct exit_function_list
  {
    struct exit_function_list *next;
    size_t idx;
    struct exit_function fns[32];
  };
```

exit_function 구조체는 이러합니다

```c++
struct exit_function
  {
    /* `flavour' should be of type of the `enum' above but since we need
       this element in an atomic operation we have to use `long int'.  */
    long int flavor;
    union
      {
	void (*at) (void);
	struct
	  {
	    void (*fn) (int status, void *arg);
	    void *arg;
	  } on;
	struct
	  {
	    void (*fn) (void *arg, int status);
	    void *arg;
	    void *dso_handle;
	  } cxa;
      } func;
  };
```

<br>

SHARED를 확인 후 __call_tls_dtors가 있는 것을 볼 수 있습니다.

보통 libc를 직접 까서 보게 되면 바로 __call_tls_dtors를 실행하는 것을 볼 수 있습니다.

```c++
#ifndef SHARED
  if (&__call_tls_dtors != NULL)
#endif
    if (run_dtors)
      __call_tls_dtors ();
```



<img src="../img/2018-10-1-exit-call-function/1.png" width="40%" height="40%">

__call_tls_dtors 를 내부를 보게 되면 0x3c3d80에서 값을 가져오고

```python
>>> ror17 = lambda x : ((x << 47) & (2**64 - 1)) | (x >> 17)
>>> hex(ror17(fs:[off_3C3D80]) ^ fd:0x30)
```

```
출처 - https://github.com/SPRITZ-Research-Group/ctf-writeups/tree/master/0x00ctf-2017/pwn/left-250
```

이러한 연산 후에 free를 호출 합니다.

<br>

다시 exit함수로 넘어와서 밑에 while문을 보도록 합시다.

<br>

잠깐 while문의 앞과 뒤를 봐봅니다.

```c++
struct exit_function_list *cur = *listp;
```

```c++
*listp = cur->next;
```

이 두줄의 코드를 보면 linked list로 된 exit_function_list를 하나 씩 cur이라는 변수에 넣어주고 있다는 걸 알 수 있습니다.

 <br>

```c++
  &cur->fns[--cur->idx];
	  switch (f->flavor)
	    {
	      void (*atfct) (void);
	      void (*onfct) (int status, void *arg);
	      void (*cxafct) (void *arg, int status);

	    case ef_free:
	    case ef_us:
	      break;
	    case ef_on:
	      onfct = f->func.on.fn;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (onfct);
#endif
	      onfct (status, f->func.on.arg);
	      break;
	    case ef_at:
	      atfct = f->func.at;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (atfct);
#endif
	      atfct ();
	      break;
	    case ef_cxa:
	      cxafct = f->func.cxa.fn;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (cxafct);
#endif
	      cxafct (f->func.cxa.arg, status);
	      break;
	    }
```

전 cur의 idx의 exit_function을 불러와 flavor에 따라 분류하는 코드입니다.

<br>

마지막 부분에는

```c++
listp = cur->next;
if (*listp != NULL)
    free (cur);
```

다음 exit_function_list 구조체가 있으면 현재 cur를 free하는 모습을 볼 수 있습니다.

<br>

<br>

<h1>exploit</h1>

방금까지 exit에 대해서 살펴봤습니다.

간단하게 익스플로잇하는 공격을 설명드리겠습니다.

<br>

pwnable에서 heap을 이용한 공격이 있을 때는 보통 \_\_free_hook 혹은 \_\_malloc_hook을 덮습니다.

그럼 free 나 malloc을 했을 때 hook을 먼저 살핀 후 값이 있을 시 실행하는데요

우린 exit에서 있는 free를 이용해 우리는 익스플로잇을 할 것입니다.

<br>

아까 보셨다시피 listp의 처음은__exit_funcs 라는 것을 알 수 있습니다.

__exit_funcs의 값인 initial 를 참조해서 코드를 실행하는데요 우린 initial 를 조작할 것입니다.

```c++
while (cur->idx > 0)
```

를 우회하고(그 밑코드를 실행 안하기 위해서)

```c++
      if (*listp != NULL)
	/* Don't free the last element in the chain, this is the statically
	   allocate element.  */
	free (cur);
    }
```

를 실행 시킬 수 있도록 할 것입니다.

<br>

일단 \_\_free_hook을 system 으로 덮습니다. 

cur(initial)->idx 를 0으로 덮습니다. 그럼 2번째 while문을 실행하지 않게 됩니다.

cur(initial)->next 를 "/bin/sh\x00" 으로 덮습니다.

이제 우린 exit할때 free를 할 수 있게 됩니다.

exit를 했을 때 free(&"/bin/sh\x00") 라는 코드를 실행 시키고

free내부에서 \_\_free_hook(&"/bin/sh\x00")를 실행시키는데

 \_\_free_hook를 system으로 덮었으므로 system(&"/bin/sh\x00") 를 실행시키므로

최종적으로 쉘을 얻게 됩니다.

<br>

<br>

<h3>들어주셔서 감사합니다. 이상한 부분은 about에 있는 연락처를 통해 연락을 주시면 매우 감사하겠습니다.</h3> 

