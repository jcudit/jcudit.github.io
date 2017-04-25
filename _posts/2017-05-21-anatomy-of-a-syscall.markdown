A syscall can be broken up into the following three phases:

* application -> `glibc`
* `glibc` -- via - software - interrupt --> `syscall_handler`
* `syscall_handler` -- via - table - lookup -> `sys_<syscall_fn>()`

Let's trace through each of the steps in detail.

## application -> glibc

This is an easy one.  Taking the `ping6` utility from the `iputils` package as
an example, we can see that the `socket()` function is called to request an
endpoint for communication from the kernel.

{% highlight c %}
int main(int argc, char *argv[])
{
    int ch, hold, packlen;
    u_char *packet;
    char *target;
    struct addrinfo hints, *ai;
    int gai;
    struct sockaddr_in6 firsthop;
    int socket_errno;
    struct icmp6_filter filter;
    int err;
#ifdef __linux__
    int csum_offset, sz_opt;
#endif
    static uint32_t scope_id = 0;

    limit_capabilities();

#ifdef USE_IDN
    setlocale(LC_ALL, "");
#endif

    enable_capability_raw();

    icmp_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    socket_errno = errno;
{% endhighlight %}

{% highlight c %}
    icmp_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
{% endhighlight %}

Note that `ping6.c` includes a header that includes another crucial header that
provides functionality for the `socket()` call:

{% highlight c %}
#include "ping_common.h"
{% endhighlight %}
{% highlight c %}
#include <sys/socket.h>
{% endhighlight %}

This leads us to the next phase - `glibc`.

## glibc --> syscall_handler

The purpose of `glibc` is to:

> provide the system API for all programs written in C and C-compatible languages
such as C++ and Objective C; the runtime facilities of other programming languages
use the C library to access the underlying operating system.

`glibc` provides functions that wrap calls into the kernel. Therefore, the
`socket()` function found in `<sys/socket.h>` is provided by `glibc`.

There is a trick to looking at how `socket()` actually signals the kernel.
It is not as straightforward as obtaining the `glibc` source code and grepping
for the correct function since code generation is in use to build the `socket()`
definition (as well as other syscalls).

`make-syscalls.sh` takes on this responsibility:

{% highlight bash %}
#! /bin/sh

# Usage: make-syscalls.sh ../sysdeps/unix/common
# Expects $sysdirs in environment.

##############################################################################
#
# This script is used to process the syscall data encoded in the various
# syscalls.list files to produce thin assembly syscall wrappers around the
# appropriate OS syscall. See syscall-template.s for more details on the
# actual wrapper.

{% endhighlight %}

During compilation of `glibc`, `make-syscalls.sh` is invoked and produces the
following for each syscall:

{% highlight bash %}
mkdir -p -- /home/vagrant/glibc-2.19/glibc-testing/socket
(echo '#define SYSCALL_NAME accept'; \
 echo '#define SYSCALL_NARGS 3'; \
 echo '#define SYSCALL_SYMBOL __libc_accept'; \
 echo '#define SYSCALL_CANCELLABLE 1'; \
 echo '#include <syscall-template.S>'; \
 echo 'weak_alias (__libc_accept, __accept)'; \
 echo 'libc_hidden_weak (__accept)'; \
 echo 'weak_alias (__libc_accept, accept)'; \
 echo 'libc_hidden_weak (accept)'; \
) | gcc -c    -I../include -I/home/vagrant/glibc-2.19/glibc-testing/socket  -I/home/vagrant/glibc-2.19/glibc-testing  -I../sysdeps/unix/sysv/linux/x86_64/64/nptl  -I../sysdeps/unix/sysv/linux/x86_64/64  -I../nptl/sysdeps/unix/sysv/linux/x86_64  -I../nptl/sysdeps/unix/sysv/linux/x86  -I../sysdeps/unix/sysv/linux/x86  -I../sysdeps/unix/sysv/linux/x86_64  -I../sysdeps/unix/sysv/linux/wordsize-64  -I../nptl/sysdeps/unix/sysv/linux  -I../nptl/sysdeps/pthread  -I../libpthread/sysdeps/pthread  -I../sysdeps/pthread  -I../ports/sysdeps/unix/sysv/linux  -I../sysdeps/unix/sysv/linux  -I../sysdeps/gnu  -I../sysdeps/unix/inet  -I../nptl/sysdeps/unix/sysv  -I../ports/sysdeps/unix/sysv  -I../sysdeps/unix/sysv  -I../sysdeps/unix/x86_64  -I../nptl/sysdeps/unix  -I../ports/sysdeps/unix  -I../sysdeps/unix  -I../sysdeps/posix  -I../libpthread/sysdeps/posix  -I../nptl/sysdeps/x86_64/64  -I../sysdeps/x86_64/64  -I../sysdeps/x86_64/fpu/multiarch  -I../sysdeps/x86_64/fpu  -I../sysdeps/x86/fpu  -I../sysdeps/x86_64/multiarch  -I../nptl/sysdeps/x86_64  -I../sysdeps/x86_64  -I../sysdeps/x86  -I../sysdeps/ieee754/ldbl-96  -I../sysdeps/ieee754/dbl-64/wordsize-64  -I../sysdeps/ieee754/dbl-64  -I../sysdeps/ieee754/flt-32  -I../sysdeps/wordsize-64  -I../sysdeps/ieee754  -I../sysdeps/generic  -I../debian  -I../libpthread/include -I../libpthread  -I../nptl  -I../ports  -I.. -I../libio -I.  -I../libpthread/include  -D_LIBC_REENTRANT -include ../include/libc-symbols.h       -DASSEMBLER  -g -Wa,--noexecstack   -o /home/vagrant/glibc-2.19/glibc-testing/socket/accept.o -x assembler-with-cpp - -MD -MP -MF /home/vagrant/glibc-2.19/glibc-testing/socket/accept.o.dt -MT /home/vagrant/glibc-2.19/glibc-testing/socket/accept.o
{% endhighlight %}

We can see that `bash` fills in syscall-specific variables and echoes some
templated C into `gcc`. An include to `syscall-template.S` pulls in the
architecture-specific method of issuing a syscall.  Peering into the series
of header files that are successively included, we are met with assembly
similar to this snippet when compiling for the x86_64 architecture:

{% highlight bash %}
#include <sysdeps/unix/sysdep.h>
#include <sysdeps/x86_64/sysdep.h>

#ifdef	__ASSEMBLER__

/* This is defined as a separate macro so that other sysdep.h files
   can include this one and then redefine DO_CALL.  */

#define DO_CALL(syscall_name, args)					      \
  lea SYS_ify (syscall_name), %rax;					      \
  syscall

#define	r0		%rax	/* Normal return-value register.  */
#define	r1		%rbx	/* Secondary return-value register.  */
#define MOVE(x,y)	movq x, y

#endif	/* __ASSEMBLER__ */
{% endhighlight %}

Note that the occurrence of `syscall` in this snippet is an assembly
instruction that is executed. This action is known as a software interrupt and
is what transitions us into the next phase within kernel space.

## `syscall_handler` -> `sys_<syscall_fn>()`

In response to the `syscall` assembly instruction, the kernel's syscall handling
code is run. Upon initialization during boot, a table mapping a syscall number
to the appropriate kernel function is loaded. Similarly, the `entry_SYSCALL_64`
assembly code is registered to be run in direct response to the `syscall`
instruction.

With these two pieces in place, a software interrupt takes the form of the
initial `syscall` instruction issued from user space, followed by the
architecture running the registered `entry_SYSCALL_64` assembly code that
provides a graceful transition into kernel space, followed by a lookup of the
syscall function matching the requested syscall number, followed by the
invocation of the actual kernel space syscall function.

The following snippet of `entry_SYSCALL_64` assembly shows the context around
the call into the resolved syscall function:

{% highlight c %}
entry_SYSCALL_64_fastpath:
	/*
	 * Easy case: enable interrupts and issue the syscall.  If the syscall
	 * needs pt_regs, we'll call a stub that disables interrupts again
	 * and jumps to the slow path.
	 */
	TRACE_IRQS_ON
	ENABLE_INTERRUPTS(CLBR_NONE)
#if __SYSCALL_MASK == ~0
	cmpq	$__NR_syscall_max, %rax
#else
	andl	$__SYSCALL_MASK, %eax
	cmpl	$__NR_syscall_max, %eax
#endif
	ja	1f				/* return -ENOSYS (already in pt_regs->ax) */
	movq	%r10, %rcx

	/*
	 * This call instruction is handled specially in stub_ptregs_64.
	 * It might end up jumping to the slow path.  If it jumps, RAX
	 * and all argument registers are clobbered.
	 */
	call	*sys_call_table(, %rax, 8)
.Lentry_SYSCALL_64_after_fastpath_call:

	movq	%rax, RAX(%rsp)
{% endhighlight %}

To be clear, the `call` here is an instruction to execute whatever is at the
address that the `sys_call_table` lookup returns:
{% highlight c %}
	call	*sys_call_table(, %rax, 8)
{% endhighlight %}

Continuing with this example, the userspace call to `socket()` would place the
value of `41` into the `%rax` register before issuing the `syscall` instruction.
This would lead to the above `call` running the `sys_socket` function, as
a result of a `sys_call_table()` lookup mapping 41 to `sys_socket()`. This
is definedj in `syscall_64.tbl` along with the other mappings for this
architecture:

{% highlight c %}
...
31	common	shmctl			sys_shmctl
32	common	dup			sys_dup
33	common	dup2			sys_dup2
34	common	pause			sys_pause
35	common	nanosleep		sys_nanosleep
36	common	getitimer		sys_getitimer
37	common	alarm			sys_alarm
38	common	setitimer		sys_setitimer
39	common	getpid			sys_getpid
40	common	sendfile		sys_sendfile64
41	common	socket			sys_socket
42	common	connect			sys_connect
43	common	accept			sys_accept
44	common	sendto			sys_sendto
...
{% endhighlight %}

Once `sys_socket()` completes, execution returns to the step just after the
syscall code to function lookup. Back in `entry_SYSCALL_64`, all work done to
swap into kernel mode is reversed so that userspace processing can resume where
it left off with the result of the requested system call.
