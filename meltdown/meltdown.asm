; ��ǿ�����ԣ������쳣������
; Ŀ�꣺���ͱ��������Ƽ�⵽�ĸ��ʣ�ͨ������ֱ�ӷ��ʷǷ���ַ�����쳣
; �޸ĵ㣺�Ƴ���ʽ�ķǷ��ڴ���ʣ����÷�֧Ԥ����󴥷�����ִ��

OutOfOrderExecution PROC
    ; ���� rcx ΪĿ���ַ��rdx Ϊ probe_array ��ַ��r8 Ϊ��֧�������ɱ������߿��ƣ�
    test   r8, r8          ; α��������֧��ʵ�� r8 ��Ϊ 0��
    jz     dummy_label     ; ��֧Ԥ���Ԥ����ת����ʵ�ʲ���ת
    ; ����ָ��������ִ����ִ��
    movzx  rax, byte ptr [rcx]  ; ��ȡĿ���ַ
    shl    rax, 12              ; ����ƫ��
    mov    al, byte ptr [rdx+rax] ; ���� probe_array
dummy_label:
    ret
OutOfOrderExecution ENDP
; ���÷�֧Ԥ����������ʽ�쳣��������ִ�У��ƹ������쳣��صķ�����

; �������򹤳̣����������
; Ŀ�꣺���ӷ���๤�ߵķ����Ѷ�,�޸ĵ㣺��������ָ�����ܴ���Ρ�
OutOfOrderExecution PROC
    db      0EBh, 02h          ; ����ת����������ࣩ
    mov     r8, qword ptr [r8]
    xor     rax, rax
    jz      valid_label        ; ����������ת�ڸ���ʵ�߼�
    ; ����ָ��
    add     rsp, 8
    sub     rsp, 8
valid_label:
    movzx   rax, byte ptr [rcx]
    shl     rax, 12
    mov     al, byte ptr [rdx+rax]
    ret
OutOfOrderExecution ENDP
; ͨ��������Чָ�����ת�������������