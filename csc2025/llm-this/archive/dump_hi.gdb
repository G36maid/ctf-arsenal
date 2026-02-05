set pagination off
starti
catch syscall write
commands
  silent
  if $rdi == 1 && $rdx == 4
    printf "=== Found Hi! write ===\n"
    printf "Dumping 200 bytes around the string:\n"
    x/200bx $rsi-50
    printf "\n\nAs ASCII:\n"
    dump binary memory /tmp/hi_region.bin $rsi-50 $rsi+150
    quit
  end
  continue
end
continue
