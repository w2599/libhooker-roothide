.text
.p2align 2
.globl _LHLegacyProtect
.private_extern _LHLegacyProtect
// 直接进入内核，避免正在修改的 libsystem 页参与权限恢复。
_LHLegacyProtect:
    mov x16, #-14
    svc #0x80
    ret

.p2align 2
.globl _LHLegacyWriterStart, _LHLegacyWriterEnd
.private_extern _LHLegacyWriterStart, _LHLegacyWriterEnd
// 可复制的叶函数：仅使用调用者保存寄存器，不访问外部代码或常量。
_LHLegacyWriterStart:
    mov x9, x0
    mov x10, x1
    mov x11, x2
    mov x12, x3
    mov w13, w4
    mov x2, x12
    mov w3, #0
    mov w4, #0x13 // READ | WRITE | COPY
    mov x16, #-14
    svc #0x80
    cbnz w0, 3f
    mov x14, #0
1:
    ldr x15, [x11, x14]
    str x15, [x10, x14]
    add x14, x14, #8
    cmp x14, x12
    b.lo 1b
    // 在返回原调用页之前恢复其权限，避免 W^X 导致同页函数失去执行权。
    mov x0, x9
    mov x1, x10
    mov x2, x12
    mov w3, #0
    mov w4, w13
    mov x16, #-14
    svc #0x80
3:
    ret
_LHLegacyWriterEnd:
