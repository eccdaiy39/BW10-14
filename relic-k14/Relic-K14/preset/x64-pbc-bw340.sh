#!/bin/bash
cmake -DFP_PRIME=340 -DWSIZE=64 -DTIMER=CYCLE -DRAND=UDEV -DSHLIB=OFF -DSTBIN=ON -DCHECK=off -DVERBS=off -DARITH=x64-asm-6l -DFP_METHD="INTEG;INTEG;INTEG;MONTY;LOWER;LOWER;SLIDE" -DEP_ENDOM=on -DEP_MUL=LWNAF -DCFLAGS="-O3 -funroll-loops -fomit-frame-pointer -finline-small-functions -march=native -mtune=native" -DFP_PMERS=off -DFP_QNRES=off -DFPX_METHD="INTEG;INTEG;LAZYR" -DEP_PLAIN=off -DEP_SUPER=off -DPP_METHD="LAZYR;OATEP" ..
