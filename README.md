# DNS
DNS Protocol Studies

```
$ gcc -o dnsclient-stage01 dnsclient-stage01.c
$ ./dnsclient-stage01
Resolving: mail.yahoo.com
Server: 8.8.4.4
Creating Query Packet ...
Length: 32

   e5 23 01 00 00 01 00 00 00 00 00 00 04 6d 61 69    |   .#...........mai   |
   6c 05 79 61 68 6f 6f 03 63 6f 6d 00 00 01 00 01    |   l.yahoo.com.....   |

Opening socket ...
Sending Query ...
Receiving Response ...
Closing socket ...
Length: 103

   e5 23 81 80 00 01 00 03 00 00 00 00 04 6d 61 69    |   .#...........mai   |
   6c 05 79 61 68 6f 6f 03 63 6f 6d 00 00 01 00 01    |   l.yahoo.com.....   |
   c0 0c 00 05 00 01 00 00 01 16 00 1b 04 65 64 67    |   .............edg   |
   65 05 67 79 63 70 69 01 62 08 79 61 68 6f 6f 64    |   e.gycpi.b.yahood   |
   6e 73 03 6e 65 74 00 c0 2c 00 01 00 01 00 00 00    |   ns.net..,.......   |
   27 00 04 57 f8 77 fc c0 2c 00 01 00 01 00 00 00    |   '..W.w..,.......   |
   27 00 04 57 f8 77 fb                               |   '..W.w.            |
```
