set pagination off
starti
catch syscall write
commands
  silent
  if $rdi == 1
    printf "=== WRITE %d bytes to stdout ===\n", $rdx
    x/40bx $rsi
    printf "String: "
    x/s $rsi
    printf "RIP: %p\n", $rip
  end
  continue
end
continue
quit
