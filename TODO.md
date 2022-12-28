### Gestion option -
```
./ft_ssl md5 - => carrer
./ft_ssl md5 -z => pas carrer
```

### Segfault
```
➜  lol ./ft_ssl md5 -s => ok
[1]    956981 segmentation fault (core dumped)  ./ft_ssl md5 -s
```

### Tu lit pas le fichier
```
➜  lol ./ft_ssl md5 -s lol lol => ok
MD5("lol")= 9cdfb439c7876e703e307864c9167a15
```

### Depends on uninitialised value
```
➜  lol valgrind ./ft_ssl md5 /dev/null
==957954== Memcheck, a memory error detector
==957954== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==957954== Using Valgrind-3.18.1 and LibVEX; rerun with -h for copyright info
==957954== Command: ./ft_ssl md5 /dev/null
==957954== 
==957954== Conditional jump or move depends on uninitialised value(s)
==957954==    at 0x10AF27: preprocess_final_output (utils.c:8)
==957954==    by 0x109979: md5_process (md5.c:73)
==957954==    by 0x1095B2: main (main.c:54)
==957954== 
==957954== Conditional jump or move depends on uninitialised value(s)
==957954==    at 0x10AF53: preprocess_final_output (utils.c:14)
==957954==    by 0x109979: md5_process (md5.c:73)
==957954==    by 0x1095B2: main (main.c:54)
==957954== 
MD5(/dev/null)= d41d8cd98f00b204e9800998ecf8427e
==957954== Conditional jump or move depends on uninitialised value(s)
==957954==    at 0x1095D2: main (main.c:57)
==957954== 
==957954== 
==957954== HEAP SUMMARY:
==957954==     in use at exit: 0 bytes in 0 blocks
==957954==   total heap usage: 7 allocs, 7 frees, 170 bytes allocated
==957954== 
==957954== All heap blocks were freed -- no leaks are possible
==957954== 
==957954== Use --track-origins=yes to see where uninitialised values come from
==957954== For lists of detected and suppressed errors, rerun with: -s
==957954== ERROR SUMMARY: 3 errors from 3 contexts (suppressed: 0 from 0)
```

### help
```
➜  lol ./ft_ssl -help => ok
Error algorithm -help not found
```

### OUUUUF sale  `Invalid Read'
```
➜  lol valgrind ./ft_ssl md5
==959351== Memcheck, a memory error detector
==959351== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==959351== Using Valgrind-3.18.1 and LibVEX; rerun with -h for copyright info
==959351== Command: ./ft_ssl md5
==959351== 
==959351== Conditional jump or move depends on uninitialised value(s)
==959351==    at 0x10AC30: fn_process (process.c:62)
==959351==    by 0x109911: md5_process (md5.c:68)
==959351==    by 0x109618: main (main.c:58)
==959351== 
efd93aaa79cbe76e758fdf2a34d19e22
efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22efd93aaa79cbe76e758fdf2a34d19e22
==959351== Invalid read of size 1
==959351==    at 0x10B6D8: ft_memcpy (in /tmp/lol/ft_ssl)
==959351==    by 0x10ADD9: fn_process (process.c:88)
==959351==    by 0x109911: md5_process (md5.c:68)
==959351==    by 0x109618: main (main.c:58)
==959351==  Address 0x4aa0081 is 0 bytes after a block of size 65 alloc'd
==959351==    at 0x4848899: malloc (in /usr/libexec/valgrind/vgpreload_memcheck-amd64-linux.so)
==959351==    by 0x10B9B1: ft_memalloc (in /tmp/lol/ft_ssl)
==959351==    by 0x10B644: ft_strnew (in /tmp/lol/ft_ssl)
==959351==    by 0x10AB25: fn_process (process.c:40)
==959351==    by 0x109911: md5_process (md5.c:68)
==959351==    by 0x109618: main (main.c:58)
==959351== 
lol
jdskahdkjs
==959351== Conditional jump or move depends on uninitialised value(s)
==959351==    at 0x10AEFB: preprocess_final_output (utils.c:6)
==959351==    by 0x109979: md5_process (md5.c:73)
==959351==    by 0x109618: main (main.c:58)
==959351== 
==959351== Conditional jump or move depends on uninitialised value(s)
==959351==    at 0x10AF07: preprocess_final_output (utils.c:6)
==959351==    by 0x109979: md5_process (md5.c:73)
==959351==    by 0x109618: main (main.c:58)
==959351== 
==959351== Conditional jump or move depends on uninitialised value(s)
==959351==    at 0x10AF27: preprocess_final_output (utils.c:8)
==959351==    by 0x109979: md5_process (md5.c:73)
==959351==    by 0x109618: main (main.c:58)
==959351== 
==959351== Conditional jump or move depends on uninitialised value(s)
==959351==    at 0x10AF53: preprocess_final_output (utils.c:14)
==959351==    by 0x109979: md5_process (md5.c:73)
==959351==    by 0x109618: main (main.c:58)
==959351== 
MD5(stdin)= 64b69c3761532cb7832be8457213b90b
==959351== 
==959351== HEAP SUMMARY:
==959351==     in use at exit: 0 bytes in 0 blocks
==959351==   total heap usage: 7 allocs, 7 frees, 170 bytes allocated
==959351== 
==959351== All heap blocks were freed -- no leaks are possible
==959351== 
==959351== Use --track-origins=yes to see where uninitialised values come from
==959351== For lists of detected and suppressed errors, rerun with: -s
==959351== ERROR SUMMARY: 36 errors from 6 contexts (suppressed: 0 from 0)
```

### Leak
```
➜  lol valgrind ./ft_ssl md5 -p lel
==959693== Memcheck, a memory error detector
==959693== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==959693== Using Valgrind-3.18.1 and LibVEX; rerun with -h for copyright info
==959693== Command: ./ft_ssl md5 -p lel
==959693== 
No such file or directory: lel
==959693== Conditional jump or move depends on uninitialised value(s)
==959693==    at 0x10AC4F: fn_process (process.c:64)
==959693==    by 0x109911: md5_process (md5.c:68)
==959693==    by 0x109618: main (main.c:58)
==959693== 
MD5("^C==959693== 
==959693== Process terminating with default action of signal 2 (SIGINT)
==959693==    at 0x4989992: read (read.c:26)
==959693==    by 0x10AE21: fn_process (process.c:80)
==959693==    by 0x109911: md5_process (md5.c:68)
==959693==    by 0x109618: main (main.c:58)
==959693== 
==959693== HEAP SUMMARY:
==959693==     in use at exit: 195 bytes in 3 blocks
==959693==   total heap usage: 4 allocs, 1 frees, 199 bytes allocated
==959693== 
==959693== LEAK SUMMARY:
==959693==    definitely lost: 65 bytes in 1 blocks
==959693==    indirectly lost: 0 bytes in 0 blocks
==959693==      possibly lost: 0 bytes in 0 blocks
==959693==    still reachable: 130 bytes in 2 blocks
==959693==         suppressed: 0 bytes in 0 blocks
==959693== Rerun with --leak-check=full to see details of leaked memory
==959693== 
==959693== Use --track-origins=yes to see where uninitialised values come from
==959693== For lists of detected and suppressed errors, rerun with: -s
==959693== ERROR SUMMARY: 1 errors from 1 contexts (suppressed: 0 from 0)
```

### Invalid Read
```
➜  lol python3 lol.py | valgrind ./ft_ssl md5
==961162== Memcheck, a memory error detector
==961162== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==961162== Using Valgrind-3.18.1 and LibVEX; rerun with -h for copyright info
==961162== Command: ./ft_ssl md5
==961162== 
==961162== Conditional jump or move depends on uninitialised value(s)
==961162==    at 0x10AC30: fn_process (process.c:62)
==961162==    by 0x109911: md5_process (md5.c:68)
==961162==    by 0x109618: main (main.c:58)
==961162== 
==961162== Invalid read of size 1
==961162==    at 0x10B6D8: ft_memcpy (in /tmp/lol/ft_ssl)
==961162==    by 0x10ADD9: fn_process (process.c:88)
==961162==    by 0x109911: md5_process (md5.c:68)
==961162==    by 0x109618: main (main.c:58)
==961162==  Address 0x4aa0081 is 0 bytes after a block of size 65 alloc'd
==961162==    at 0x4848899: malloc (in /usr/libexec/valgrind/vgpreload_memcheck-amd64-linux.so)
==961162==    by 0x10B9B1: ft_memalloc (in /tmp/lol/ft_ssl)
==961162==    by 0x10B644: ft_strnew (in /tmp/lol/ft_ssl)
==961162==    by 0x10AB25: fn_process (process.c:40)
==961162==    by 0x109911: md5_process (md5.c:68)
==961162==    by 0x109618: main (main.c:58)
==961162== 
==961162== Conditional jump or move depends on uninitialised value(s)
==961162==    at 0x10AEFB: preprocess_final_output (utils.c:6)
==961162==    by 0x109979: md5_process (md5.c:73)
==961162==    by 0x109618: main (main.c:58)
==961162== 
==961162== Conditional jump or move depends on uninitialised value(s)
==961162==    at 0x10AF07: preprocess_final_output (utils.c:6)
==961162==    by 0x109979: md5_process (md5.c:73)
==961162==    by 0x109618: main (main.c:58)
==961162== 
==961162== Conditional jump or move depends on uninitialised value(s)
==961162==    at 0x10AF27: preprocess_final_output (utils.c:8)
==961162==    by 0x109979: md5_process (md5.c:73)
==961162==    by 0x109618: main (main.c:58)
==961162== 
==961162== Conditional jump or move depends on uninitialised value(s)
==961162==    at 0x10AF53: preprocess_final_output (utils.c:14)
==961162==    by 0x109979: md5_process (md5.c:73)
==961162==    by 0x109618: main (main.c:58)
==961162== 
MD5(stdin)= 7ddc2b679c53450c59b8fd028d4ac3bb
==961162== 
==961162== HEAP SUMMARY:
==961162==     in use at exit: 0 bytes in 0 blocks
==961162==   total heap usage: 7 allocs, 7 frees, 170 bytes allocated
==961162== 
==961162== All heap blocks were freed -- no leaks are possible
==961162== 
==961162== Use --track-origins=yes to see where uninitialised values come from
==961162== For lists of detected and suppressed errors, rerun with: -s
==961162== ERROR SUMMARY: 1915 errors from 6 contexts (suppressed: 0 from 0)
```

### Porque esta dos hashos
```
➜  lol  ./ft_ssl md5 -s lol -s lel -s '' -s 'bite'        
MD5("lol")= 9cdfb439c7876e703e307864c9167a15
MD5("")= d41d8cd98f00b204e9800998ecf8427e
```

### Folder
```
➜  lol ./ft_ssl md5 src         
[1]    963680 segmentation fault (core dumped)  ./ft_ssl md5 src
```