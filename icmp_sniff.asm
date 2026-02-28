section .bss
    fd_no resb 4                ; File descriptor for the raw socket
    sniffed_data resb 1200      ; Buffer for incoming raw packets
    incoming_addr resb 16       ; Buffer for sockaddr_in structure (IP/Port details)
    addr_len      resd 1        ; Length of sockaddr_in structure (4 bytes is sufficient)
    addr_ip resb 16             ; Buffer for the formatted IPv4 string

section .data
    newline db 10               ; Newline character (\n)
    forip db 4                  ; Counter for IP octets
    space_char db 32            ; Space character for output formatting

section .text
global _start

; INITIALIZE RAW SOCKET (AF_INET, SOCK_RAW, IPPROTO_ICMP)
_start:
    mov rax, 41                 ; sys_socket
    mov rdi, 2                  ; AF_INET (IPv4)
    mov rsi, 3                  ; SOCK_RAW (Raw socket access)
    mov rdx, 1                  ; IPPROTO_ICMP (ICMP protocol)
    syscall                     ; Returns the socket file descriptor in rax
    mov [fd_no], eax            ; Store the socket file descriptor in memory
;-----------------------------------------------------------------------------------------

_sniff:
; SET UP PARAMETERS FOR RECVFROM SYSCALL
    mov dword [addr_len], 16    ; Initialize sockaddr_in length to 16 bytes
    mov r8, incoming_addr       ; Pointer to sockaddr_in buffer
    mov r9, addr_len            ; Pointer to length variable
    xor r10, r10                ; Clear r10 (Flags = 0)
;------------------------------------------------------------------------------------------

; CAPTURE INCOMING ICMP PACKETS
    mov rax, 45                 ; sys_recvfrom
    mov edi, [fd_no]            ; Socket file descriptor
    mov rsi, sniffed_data       ; Destination buffer for the packet
    mov rdx, 1200               ; Maximum bytes to read
    syscall
;------------------------------------------------------------------------------------------

    cmp rax, 0                  ; Check for syscall errors
    jl _error
    je _exit

; VERIFY PACKET SIZE
    cmp rax, 28                 ; Check if packet is at least 28 bytes (20B IP + 8B ICMP Header)
    jb _sniff                   ; If smaller, ignore and wait for the next packet
;-----------------------------------------------------------------------------------------------

; EXTRACT PAYLOAD: STRIP IP AND ICMP HEADERS. PRESERVE REGISTERS FOR WRITE SYSCALL.

    mov r14, rax                ; r14 holds total received bytes
    sub r14, 28                 ; Calculate payload size (Total - 28 bytes of headers)
    lea rsi, [sniffed_data + 28]; rsi points to the exact start of the ICMP payload
    mov rdx, r14                ; rdx holds the length of the payload
    push rdx                    ; Preserve payload length
    push rsi                    ; Preserve payload address

; IP ADDRESS TO STRING ALGORITHM (EXTRACT REVERSE BYTE-BY-BYTE AND CONVERT TO ASCII)
    xor rdx, rdx                ; Clear rdx
    xor rbx, rbx                ; Clear rbx
    mov rcx, 7                  ; Start index for reading IP from sockaddr_in (sin_addr offset)
    mov rdi, 15                 ; Start index for writing to the addr_ip buffer (backwards)
_loopforip:
    mov bl, 10                  ; Divisor for base-10 conversion
    movzx ax, [incoming_addr+rcx] ; Fetch one octet from IP address
_divloop:
    div bl                      ; Divide AX by 10; AL = quotient, AH = remainder
    add ah, 48                  ; Convert remainder to ASCII character
    mov [addr_ip+rdi], ah       ; Store ASCII character in the output buffer
    dec rdi                     ; Move buffer pointer backward
    xor ah, ah                  ; Clear AH for the next division cycle
    cmp al, 0                   ; Check if quotient is zero
    jg _divloop                 ; If not zero, continue extracting digits
    
    cmp rcx, 4                  ; Check if this is the last octet (first IP block)
    je _contiune                ; If last octet, skip adding the dot separator
    mov byte [addr_ip+rdi], 46  ; Insert '.' (dot) character
_contiune:
    dec rdi                     ; Move buffer pointer backward for the next octet
    dec rcx                     ; Move to the next IP octet in sockaddr_in
    cmp rcx, 3                  ; Check if all 4 octets have been processed
    jg _loopforip               ; Loop until the entire IP is converted
;-----------------------------------------------------

; WRITE THE FORMATTED IP ADDRESS TO STDOUT
    mov rax, 1                  ; sys_write
    mov rdi, 1                  ; File descriptor 1 (stdout)
    mov rdx, 16                 ; Length to write
    mov rsi, addr_ip            ; Pointer to the formatted IP string
    syscall

; WRITE A SPACE SEPARATOR FOR OUTPUT FORMATTING
    mov rax, 1                  ; sys_write
    mov rdi, 1                  ; File descriptor 1 (stdout)
    mov rdx, 1                  ; Length of space
    mov rsi, space_char         ; Pointer to space character
    syscall
;------------------------------------------------------
    
    pop rsi                     ; Restore payload address from stack
    pop rdx                     ; Restore payload length from stack

; WRITE THE EXTRACTED ICMP PAYLOAD
    mov rax, 1                  ; sys_write
    mov rdi, 1                  ; File descriptor 1 (stdout)
    syscall
;-----------------------------------------------------

; WRITE NEWLINE TO PREVENT OUTPUT OVERLAPPING
    mov rax, 1                  ; sys_write
    mov rdi, 1                  ; File descriptor 1 (stdout)
    mov rsi, newline            ; Pointer to newline character
    mov rdx, 1                  ; Length of newline
    syscall
;------------------------------------------------------
    jmp _sniff                  ; Loop back to listen for the next packet

; EXIT ROUTINES (ERROR HANDLING)
_error:
    mov rax, 60                 ; sys_exit
    mov rdi, 1                  ; Exit code 1 (Error)
    syscall
;------------------------------------------------------

; EXIT ROUTINES (GRACEFUL EXIT)
_exit:
    mov rax, 60                 ; sys_exit
    mov rdi, 0                  ; Exit code 0 (Success)
    syscall
;------------------------------------------------------
