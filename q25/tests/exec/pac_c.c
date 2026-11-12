// SPDX-License-Identifier: MIT
// Freestanding C program built with return address signing (PACIBSP / RETAB).
// Prints a checksum computed through recursion and indirect calls.
typedef unsigned long u64;

static long sys3(long n, long a, long b, long c)
{
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}

__attribute__((noinline)) static u64 fib(u64 n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
__attribute__((noinline)) static u64 mix(u64 a, u64 b) { return (a ^ (b << 7)) * 0x9e3779b97f4a7c15UL + (a >> 3); }
__attribute__((noinline)) static u64 twice(u64 (*f)(u64, u64), u64 a, u64 b) { return f(f(a, b), b); }

__attribute__((noinline)) static u64 walk(u64 depth, u64 acc)
{
    volatile u64 pad[4];
    pad[depth & 3] = acc;
    if (depth == 0) {
        return acc;
    }
    return walk(depth - 1, mix(acc, pad[depth & 3] + depth));
}

static void put_hex(u64 v)
{
    char buf[19];
    buf[0] = '0'; buf[1] = 'x';
    for (int i = 0; i < 16; i++) {
        unsigned d = (v >> (60 - 4 * i)) & 15;
        buf[2 + i] = d < 10 ? '0' + d : 'a' + d - 10;
    }
    buf[18] = '\n';
    sys3(64, 1, (long)buf, 19);
}

void _start(void)
{
    u64 r = fib(24);
    r = twice(mix, r, 0x1234);
    r = walk(200, r);
    put_hex(r);
    sys3(93, 0, 0, 0);
    for (;;) { }
}
