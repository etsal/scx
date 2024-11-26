libprog = ['sdt_task']

foreach prog: libprog
  thread_dep = dependency('threads')
  bpf_o = gen_bpf_o.process(prog + '.bpf.c', extra_args: bpf_includes)
  custom_target(prog,
    input: prog + '.bpf.c',
    output: prog + '.bpf.o',
    command: ['true'],)
endforeach
