/*
 *  This file is part of the SGX-Step enclave execution control framework.
 *
 *  Copyright (C) 2017 Jo Van Bulck <jo.vanbulck@cs.kuleuven.be>,
 *                     Raoul Strackx <raoul.strackx@cs.kuleuven.be>
 *
 *  SGX-Step is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  SGX-Step is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with SGX-Step. If not, see <http://www.gnu.org/licenses/>.
 */

    .macro lea_pic symbol, reg
        lea   \symbol(%rip), \reg
    .endm

    .text
    .global zigzag_bench
    .align 0x1000   /* 4KiB */
    .type zigzag_bench,@function
// code snippet from
// https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-lee-sangho.pdf

// loop count -> rdi
// a -> rsi
// b -> rdx
zigzag_bench:
            push %rdi
            push %r14
            push %r15
zigzag_loop:
            cmp $0, %rdi
            je zigzag_bench_ret

block0:     lea_pic block1, %r15
            lea_pic block2, %r14
            cmp $0, %rsi 
            cmove %r14, %r15
block0.j:   jmp zz1
block1:     nop 
            lea_pic block5, %r15
block1.j:   jmp zz2
block2:     lea_pic block3, %r15
            lea_pic block4, %r14
            cmp $0, %rdx
            cmove %r14, %r15
block2.j:   jmp zz3
block3:     nop
            lea_pic block5, %r15
block3.j:   jmp zz4
block4:     nop
block5:     nop
            dec %rdi
            jmp zigzag_loop

zigzag_bench_ret:
            pop %r15
            pop %r14
            pop %rdi
            retq

zz1:        jmp block1.j
zz2:        jmp block2.j
zz3:        jmp block3.j
zz4:        jmpq *%r15
