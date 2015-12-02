#!/usr/bin/env python3

# these are syscalls which are always allowed from speculative tasks
allowed_syscalls = [
    35,  # nanosleep
    96,  # gettimeofday
]

# these are syscalls which are only allowed if we are irrevocable (like file
# output)
irrevocable_syscalls = [
    # 0,   # read
    # 1,   # write
    # 3,   # close
]

# the whole rest will be disallowed and lead to an abort...


# there exist syscalls 0 .. 313
num_syscalls = 314


def func(name, scope='local'):
    return '''
        .align 16, 0x90
        .{1} {0}
        {0}:
    '''.format(name, scope)

print('''
    .local ktls_old_syscall_targets
    .comm ktls_old_syscall_targets,{0},16

    '''.format(8*num_syscalls)
      + func('ktls_redirect_system_calls', 'global')
      + '''
    push %rdi
    movq %rsi, %rax
    movq %rdi, %rsi
    and $-4096, %rdi
    add ${0}, %rsi
    sub %rdi, %rsi
    add $4095, %rsi
    shr $12, %rsi
    call *%rax
    pop %rdi
    mov %cr0, %rax
    push %rax
    and $0xfffffffffffeffff, %rax
    mov %rax, %cr0
'''.format(8*num_syscalls))

for nr in range(num_syscalls):
    if nr in allowed_syscalls:
        continue
    print('''
        movq {1}(%rdi), %rax
        movq %rax, ktls_old_syscall_targets+{1}(%rip)
        movq $ktls_syscall_jump_{0}, {1}(%rdi)
    '''.format(nr, 8*nr))

print('''
    pop %rax
    mov %rax, %cr0
    ret

    ''' + func('ktls_restore_system_calls', 'global') + '''
    mov %cr0, %rax
    push %rax
    and $0xfffffffffffeffff, %rax
    mov %rax, %cr0
''')

for nr in range(num_syscalls):
    if nr in allowed_syscalls:
        continue
    print('''
        movq ktls_old_syscall_targets+{0}(%rip), %rax
        movq %rax, {0}(%rdi)
    '''.format(8*nr))

print('''
    pop %rax
    mov %rax, %cr0
    ret
''')


for nr in range(num_syscalls):
    print(func('ktls_syscall_jump_'+str(nr)) + '''
        mov ${0}, %eax
        jmp ktls_syscall_{1}_trampoline
'''.format(nr, 'irrevocable' if nr in irrevocable_syscalls else 'forbidden'))

for type in ('irrevocable', 'forbidden'):
    print(func('ktls_syscall_'+type+'_trampoline') + '''
        push %rdi
        push %rsi
        push %rdx
        push %rcx
        push %r8
        push %r9
        movq %rax, %rdi
        push %rax
        call ktls_syscall_{0}
        pop %rax
        pop %r9
        pop %r8
        pop %rcx
        pop %rdx
        pop %rsi
        pop %rdi
        jmpq *ktls_old_syscall_targets(,%rax,8)
    '''.format(type))
