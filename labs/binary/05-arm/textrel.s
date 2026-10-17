@ A text relocation: a literal pool in .text holds msg's absolute address, so a PIE build needs
@ the loader to patch the code page (linked with -z notext). Never run; it exists to be analysed.
.arm
.text
.globl _start
.type _start, %function
_start:
  ldr r0, 1f
  udf #0
1: .word msg
.data
msg: .asciz "patched at load time"
