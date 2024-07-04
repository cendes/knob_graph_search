# Running the code

1 - Download and extract the Linux kernel source code:

```
wget https://mirrors.edge.kernel.org/pub/linux/kernel/v5.x/linux-5.15.152.tar.gz
tar -xvzf linux-5.15.152.tar.gz  
```

2 - cd into the extracted Linux source code directory and delete some of the files:

```
cd linux-5.15.152
rm arch/x86/realmode/rm/realmode.h && rm arch/x86/entry/vdso/extable.h && rm include/linux/linkage.h && rm include/linux/objtool.h && rm tools/arch/x86/include/asm/asm.h && rm tools/include/linux/objtool.h
```

3 - Generate the cscope database (run this inside the Linux source code directory):

```
cscope -R -b -k
```

4 - Leave the Linux source code directory and compile the knob search program:

```
cd ..
make all
```

5 - Run the knob search program:
```
./knob_search [name of sysctl knob] linux-5.15.152
```
