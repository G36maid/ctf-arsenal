set pagination off
set logging file gdb_trace_full.log
set logging on
catch syscall write
commands
  silent
  if $rdi == 1
    printf "=== WRITE to stdout (fd=1) ===\n"
    printf "Address: %p\n", $rsi
    printf "Size: %d\n", $rdx
    x/4bx $rsi
    x/s $rsi
    printf "Backtrace:\n"
    bt 5
    printf "================================\n"
  end
  continue
end
run <<< "test"
quit
