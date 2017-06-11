# reverse-from-coredump
Reverse Execution From CoreDump

## Prerequirement

### libelf / libdisasm

    $ sudo apt-get install libelf1 libelf-dev

library to read and write ELF files

~~$ sudo apt-get install libdisasm0 libdisasm-dev~~

~~disassembler library for x86 code~~

### custome-tailor libdisasm

Now we use a custome-tailor [libdisasm](https://github.com/junxzm1990/libdsiasm). The corresponding installation process is as follows:

```sh
cd libdsiasm
./configure
make
sudo make install

sudo ldconfig
```

### autoconf / automake

    $ sudo apt-get install autoconf automake

## Building

```
$ ./autogen.sh
$ ./configure
$ make
```

## Usage

    $ ./src/reverse coredump binary_path inversed_instruction_trace

**Make sure binary file and all the library files are in the binary path**

### Test

```
$ ./src/reverse testsuites/latex2rtf/core testsuites/library/ testsuites/latex2rtf/inst.reverse
```

### Clean

```
$ make clean
$ make distclean
```

## Branch

### master

Keep stable functionability in this branch

### test1

Test alias resovler in this branch

### debugging

migrate some features from test1 and test here

### Other branch

The following branches are used for testcases:

- coreutils
- uniq
- join
- latex2rtf
- stftp
- inetutils
- binutils
- openjpeg
- podofo
- unalz
- unrtf
- psutils
- poppler
- mcrypt
- putty
- python22

For other cases, like 0verkill, nasm, there is no separate branch, due to failure.

### Testcases needed to test

- corehttp
- gif2png
- store
- gdb


## Instructions Handler

- [x] add
- [x] sub
- [x] mul
- [x] div
- [x] inc
- [x] dec
- [x] shl
- [x] shr
- [x] rol
- [x] ror
- [x] and
- [x] or
- [x] xor
- [x] not
- [x] neg
- [x] return
- [x] call
- [x] jmp
- [x] jcc
- [x] push
- [x] pop
- [ ] pushregs
- [ ] popregs
- [ ] pushflags
- [ ] popflags
- [ ] enter
- [x] leave
- [x] test
- [x] cmp
- [x] mov
- [x] lea
- [x] movcc (Examples: setz)
- [x] xchg
- [x] xchgcc (Exmaples: cmpxchg)
- [x] strcmp
- [x] strload
- [x] strmov
- [x] strstore
- [ ] translate
- [x] bittest
- [x] bitset
- [x] bitclear
- [x] cpuid
- [x] nop

## Instruction Resolver

- [x] add
- [x] sub
- [x] mul
- [x] div
- [x] inc
- [x] dec
- [x] shl
- [x] shr
- [x] rol
- [x] ror
- [x] and
- [x] or
- [x] xor
- [x] not
- [x] neg
- [x] return
- [x] call
- [x] jmp
- [x] jcc
- [x] push
- [x] pop
- [ ] pushregs
- [ ] popregs
- [ ] pushflags
- [ ] popflags
- [ ] enter
- [x] leave
- [x] test
- [x] cmp
- [x] mov
- [x] lea
- [x] movcc (Examples: setz)
- [x] xchg
- [x] xchgcc (Exmaples: cmpxchg)
- [x] strcmp
- [x] strload
- [x] strmov
- [x] strstore
- [ ] translate
- [x] bittest
- [x] bitset
- [x] bitclear
- [x] cpuid
- [x] nop
