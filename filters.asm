.data

; Syscall numbers
extern gSsn_Filter_LoadImage:DWORD
extern gSsn_Filter_AllocateData:DWORD
extern gSsn_Filter_ApplyEffect:DWORD
extern gSsn_Filter_StartJob:DWORD
extern gSsn_Filter_WaitJob:DWORD
extern gSsn_Filter_FreeData:DWORD
extern gSsn_Filter_CloseJob:DWORD

extern gSsn_Filter_ResumeJob:DWORD
extern gSsn_Filter_OpenWorker:DWORD
extern gSsn_Filter_QueueTask:DWORD
extern gSsn_Filter_GetInfo:DWORD
extern gSsn_Filter_GetSystemState:DWORD

; Syscall execution stubs
extern gStub_Filter_LoadImage:QWORD
extern gStub_Filter_AllocateData:QWORD
extern gStub_Filter_ApplyEffect:QWORD
extern gStub_Filter_StartJob:QWORD
extern gStub_Filter_WaitJob:QWORD
extern gStub_Filter_FreeData:QWORD
extern gStub_Filter_CloseJob:QWORD

extern gStub_Filter_ResumeJob:QWORD
extern gStub_Filter_OpenWorker:QWORD
extern gStub_Filter_QueueTask:QWORD
extern gStub_Filter_GetInfo:QWORD
extern gStub_Filter_GetSystemState:QWORD

.code

Filter_LoadImage proc
    mov r10, rcx
    mov eax, gSsn_Filter_LoadImage
    jmp qword ptr gStub_Filter_LoadImage
Filter_LoadImage endp

Filter_AllocateData proc
    mov r10, rcx
    mov eax, gSsn_Filter_AllocateData
    jmp qword ptr gStub_Filter_AllocateData
Filter_AllocateData endp

Filter_ApplyEffect proc
    mov r10, rcx
    mov eax, gSsn_Filter_ApplyEffect
    jmp qword ptr gStub_Filter_ApplyEffect
Filter_ApplyEffect endp

Filter_StartJob proc
    mov r10, rcx
    mov eax, gSsn_Filter_StartJob
    jmp qword ptr gStub_Filter_StartJob
Filter_StartJob endp

Filter_WaitJob proc
    mov r10, rcx
    mov eax, gSsn_Filter_WaitJob
    jmp qword ptr gStub_Filter_WaitJob
Filter_WaitJob endp

Filter_FreeData proc
    mov r10, rcx
    mov eax, gSsn_Filter_FreeData
    jmp qword ptr gStub_Filter_FreeData
Filter_FreeData endp

Filter_CloseJob proc
    mov r10, rcx
    mov eax, gSsn_Filter_CloseJob
    jmp qword ptr gStub_Filter_CloseJob
Filter_CloseJob endp

Filter_ResumeJob proc
    mov r10, rcx
    mov eax, gSsn_Filter_ResumeJob
    jmp qword ptr gStub_Filter_ResumeJob
Filter_ResumeJob endp

Filter_OpenWorker proc
    mov r10, rcx
    mov eax, gSsn_Filter_OpenWorker
    jmp qword ptr gStub_Filter_OpenWorker
Filter_OpenWorker endp

Filter_QueueTask proc
    mov r10, rcx
    mov eax, gSsn_Filter_QueueTask
    jmp qword ptr gStub_Filter_QueueTask
Filter_QueueTask endp

Filter_GetInfo proc
    mov r10, rcx
    mov eax, gSsn_Filter_GetInfo
    jmp qword ptr gStub_Filter_GetInfo
Filter_GetInfo endp

Filter_GetSystemState proc
    mov r10, rcx
    mov eax, gSsn_Filter_GetSystemState
    jmp qword ptr gStub_Filter_GetSystemState
Filter_GetSystemState endp

end
