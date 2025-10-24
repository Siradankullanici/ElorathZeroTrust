﻿// Regedit.c - Registry protection with user-mode alerting (FIXED)
#include "Driver_Regedit.h"
#include <ntstrsafe.h>

#define REG_TAG 'gkER'
#define REG_PROTECT_SUBPATH L"\\SOFTWARE\\OWLYSHIELD"
#define REG_PROTECT_KEY L"\\Services\\HydraDragonAntivirus"
#define REG_PROTECT_PYAS L"\\Services\\SimplePYASProtection"
#define REG_PROTECT_OWLY L"\\Services\\owlyshield_ransom"
#define REG_PROTECT_SANCTUM L"\\Services\\sanctum_ppl_runner"

LARGE_INTEGER Cookie;

// Work item for deferred registry alerts
typedef struct _REGISTRY_ALERT_WORK_ITEM {
    WORK_QUEUE_ITEM WorkItem;
    UNICODE_STRING RegPath;
    UNICODE_STRING AttackerPath;
    HANDLE AttackerPid;
    WCHAR Operation[64];
} REGISTRY_ALERT_WORK_ITEM, * PREGISTRY_ALERT_WORK_ITEM;

// Prototypes
NTSTATUS RegistryCallback(_In_ PVOID CallbackContext, _In_ PVOID Argument1, _In_ PVOID Argument2);
VOID RegistryAlertWorker(PVOID Context);
NTSTATUS QueueRegistryAlertToUserMode(PUNICODE_STRING RegPath, PCWSTR Operation);

// NOTE: Function definitions now have SAL annotations matching the header file.
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN GetNameForRegistryObject(
    _Inout_ _At_(pRegistryPath->Buffer, _Pre_writable_byte_size_(pRegistryPath->MaximumLength) _Post_z_)
    PUNICODE_STRING pRegistryPath,
    _In_  PVOID pRegistryObject
);

BOOLEAN UnicodeContainsInsensitive(_In_ PUNICODE_STRING Source, _In_ PCWSTR Pattern);


NTSTATUS RegeditDriverEntry()
{
    NTSTATUS status = CmRegisterCallback(RegistryCallback, NULL, &Cookie);
    if (NT_SUCCESS(status))
    {
        DbgPrint("[Registry-Protection] Initialized successfully\r\n");
    }
    else
    {
        DbgPrint("[Registry-Protection] Failed to initialize: 0x%X\r\n", status);
    }
    return status;
}

NTSTATUS RegeditUnloadDriver()
{
    if (Cookie.QuadPart != 0)
    {
        CmUnRegisterCallback(Cookie);
        Cookie.QuadPart = 0;
    }
    DbgPrint("[Registry-Protection] Unloaded\r\n");
    return STATUS_SUCCESS;
}

// Worker routine running at PASSIVE_LEVEL
VOID RegistryAlertWorker(PVOID Context)
{
    PREGISTRY_ALERT_WORK_ITEM workItem = (PREGISTRY_ALERT_WORK_ITEM)Context;
    NTSTATUS status;
    HANDLE pipeHandle = NULL;
    IO_STATUS_BLOCK ioStatusBlock;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING pipeName;
    WCHAR messageBuffer[2048];
    WCHAR escapedRegPath[1024];

    RtlInitUnicodeString(&pipeName, SELF_DEFENSE_PIPE_NAME);

    InitializeObjectAttributes(
        &objAttr,
        &pipeName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    // Open pipe
    status = ZwCreateFile(
        &pipeHandle,
        FILE_WRITE_DATA | SYNCHRONIZE,
        &objAttr,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL,
        0
    );

    if (!NT_SUCCESS(status))
    {
        goto Cleanup;
    }

    PCWSTR attackerName = workItem->AttackerPath.Buffer ? workItem->AttackerPath.Buffer : L"Unknown";

    // Escape backslashes in registry path for JSON
    RtlZeroMemory(escapedRegPath, sizeof(escapedRegPath));

    if (workItem->RegPath.Buffer && workItem->RegPath.Length > 0)
    {
        ULONG j = 0;
        for (ULONG i = 0; i < workItem->RegPath.Length / sizeof(WCHAR) && j + 1 < ARRAYSIZE(escapedRegPath); ++i)
        {
            if (workItem->RegPath.Buffer[i] == L'\\')
            {
                if (j + 2 < ARRAYSIZE(escapedRegPath)) {
                    escapedRegPath[j++] = L'\\';
                    escapedRegPath[j++] = L'\\';
                }
            }
            else
            {
                escapedRegPath[j++] = workItem->RegPath.Buffer[i];
            }
        }
        escapedRegPath[j] = L'\0';
    }

    // Build JSON message
    RtlZeroMemory(messageBuffer, sizeof(messageBuffer));
    status = RtlStringCbPrintfW(
        messageBuffer,
        sizeof(messageBuffer),
        L"{\"protected_file\":\"%s\",\"attacker_path\":\"%s\",\"attacker_pid\":%llu,\"attack_type\":\"REGISTRY_TAMPERING\",\"operation\":\"%s\"}",
        escapedRegPath[0] ? escapedRegPath : L"",
        attackerName,
        (ULONGLONG)(ULONG_PTR)workItem->AttackerPid,
        workItem->Operation
    );

    if (!NT_SUCCESS(status))
    {
        ZwClose(pipeHandle);
        goto Cleanup;
    }

    SIZE_T messageLength = wcslen(messageBuffer) * sizeof(WCHAR);

    // Write to pipe
    status = ZwWriteFile(
        pipeHandle,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        messageBuffer,
        (ULONG)messageLength,
        NULL,
        NULL
    );

    ZwClose(pipeHandle);

    if (NT_SUCCESS(status))
    {
        // FIXED: Changed format specifier for Operation from %s to %ws to correctly print a wide character string.
        DbgPrint("[Registry-Protection] Alert sent: PID %llu attempted %ws on %wZ\r\n",
            (ULONGLONG)(ULONG_PTR)workItem->AttackerPid,
            workItem->Operation,
            &workItem->RegPath);
    }

Cleanup:
    // Free allocated strings
    if (workItem->RegPath.Buffer)
        ExFreePoolWithTag(workItem->RegPath.Buffer, REG_TAG);
    if (workItem->AttackerPath.Buffer)
        ExFreePool(workItem->AttackerPath.Buffer);

    ExFreePoolWithTag(workItem, REG_TAG);
}

NTSTATUS QueueRegistryAlertToUserMode(
    PUNICODE_STRING RegPath,
    PCWSTR Operation
)
{
    PREGISTRY_ALERT_WORK_ITEM workItem;
    PEPROCESS currentProcess = PsGetCurrentProcess();
    HANDLE currentPid = PsGetCurrentProcessId();
    PUNICODE_STRING attackerPath = NULL;
    NTSTATUS status;

    // Allocate work item
    workItem = (PREGISTRY_ALERT_WORK_ITEM)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(REGISTRY_ALERT_WORK_ITEM),
        REG_TAG
    );

    if (!workItem)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(workItem, sizeof(REGISTRY_ALERT_WORK_ITEM));

    // Copy registry path
    if (RegPath && RegPath->Buffer && RegPath->Length > 0)
    {
        workItem->RegPath.Length = RegPath->Length;
        workItem->RegPath.MaximumLength = RegPath->Length + sizeof(WCHAR);
        workItem->RegPath.Buffer = (PWCHAR)ExAllocatePoolWithTag(
            NonPagedPool,
            workItem->RegPath.MaximumLength,
            REG_TAG
        );

        if (workItem->RegPath.Buffer)
        {
            RtlCopyMemory(workItem->RegPath.Buffer, RegPath->Buffer, RegPath->Length);
            workItem->RegPath.Buffer[RegPath->Length / sizeof(WCHAR)] = L'\0';
        }
    }

    // Get attacker process path
    status = SeLocateProcessImageName(currentProcess, &attackerPath);
    if (NT_SUCCESS(status) && attackerPath && attackerPath->Buffer && attackerPath->Length > 0)
    {
        workItem->AttackerPath.Length = attackerPath->Length;
        workItem->AttackerPath.MaximumLength = attackerPath->Length + sizeof(WCHAR);
        workItem->AttackerPath.Buffer = (PWCHAR)ExAllocatePoolWithTag(
            NonPagedPool,
            workItem->AttackerPath.MaximumLength,
            REG_TAG
        );

        if (workItem->AttackerPath.Buffer)
        {
            RtlCopyMemory(workItem->AttackerPath.Buffer, attackerPath->Buffer, attackerPath->Length);
            workItem->AttackerPath.Buffer[attackerPath->Length / sizeof(WCHAR)] = L'\0';
        }
    }

    // Free the allocated path from SeLocateProcessImageName
    if (attackerPath)
        ExFreePool(attackerPath);

    // Copy PID and operation
    workItem->AttackerPid = currentPid;
    RtlStringCbCopyW(workItem->Operation, sizeof(workItem->Operation), Operation);

    // Queue work item
    ExInitializeWorkItem(&workItem->WorkItem, RegistryAlertWorker, workItem);
    ExQueueWorkItem(&workItem->WorkItem, DelayedWorkQueue);

    return STATUS_SUCCESS;
}

// FIXED: Added full SAL annotations to the function DEFINITION to match the DECLARATION in the header file.
// This resolves the "inconsistent annotation" and "uninitialized memory" warnings.
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN GetNameForRegistryObject(
    _Inout_ _At_(pRegistryPath->Buffer, _Pre_writable_byte_size_(pRegistryPath->MaximumLength) _Post_z_)
    PUNICODE_STRING pRegistryPath,
    _In_  PVOID pRegistryObject)
{
    if (!pRegistryPath || pRegistryPath->MaximumLength == 0 || !pRegistryPath->Buffer)
        return FALSE;

    // Explicitly initialize the Length to 0 to satisfy the static analyzer that we are not reading uninitialized memory.
    pRegistryPath->Length = 0;

    if (!pRegistryObject || !MmIsAddressValid(pRegistryObject))
        return FALSE;

    NTSTATUS Status;
    ULONG ReturnLen = 0;
    POBJECT_NAME_INFORMATION NameInfo = NULL;

    // First call to get required length
    Status = ObQueryNameString(pRegistryObject, NULL, 0, &ReturnLen);
    if (Status != STATUS_INFO_LENGTH_MISMATCH || ReturnLen == 0)
        return FALSE;

    NameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ReturnLen, REG_TAG);
    if (!NameInfo)
        return FALSE;

    RtlZeroMemory(NameInfo, ReturnLen);

    Status = ObQueryNameString(pRegistryObject, NameInfo, ReturnLen, &ReturnLen);
    if (!NT_SUCCESS(Status) || NameInfo->Name.Length == 0)
    {
        ExFreePoolWithTag(NameInfo, REG_TAG);
        return FALSE;
    }

    // Ensure destination buffer is large enough
    if (NameInfo->Name.Length > pRegistryPath->MaximumLength)
    {
        ExFreePoolWithTag(NameInfo, REG_TAG);
        return FALSE;
    }

    // Copy into caller-provided UNICODE_STRING
    RtlCopyUnicodeString(pRegistryPath, &NameInfo->Name);

    ExFreePoolWithTag(NameInfo, REG_TAG);
    return TRUE;
}

// Case-insensitive substring search: returns TRUE if Pattern exists in Source
BOOLEAN UnicodeContainsInsensitive(_In_ PUNICODE_STRING Source, _In_ PCWSTR Pattern)
{
    if (!Source || !Source->Buffer || Source->Length == 0 || !Pattern)
        return FALSE;

    UNICODE_STRING srcUp = { 0 }, patUp = { 0 };
    UNICODE_STRING pat;
    RtlInitUnicodeString(&pat, Pattern);

    if (!NT_SUCCESS(RtlUpcaseUnicodeString(&srcUp, Source, TRUE)))
        return FALSE;
    if (!NT_SUCCESS(RtlUpcaseUnicodeString(&patUp, &pat, TRUE)))
    {
        RtlFreeUnicodeString(&srcUp);
        return FALSE;
    }

    BOOLEAN found = FALSE;
    ULONG srcChars = srcUp.Length / sizeof(WCHAR);
    ULONG patChars = patUp.Length / sizeof(WCHAR);

    if (patChars > 0 && patChars <= srcChars)
    {
        PWCHAR s = srcUp.Buffer;
        PWCHAR p = patUp.Buffer;
        for (ULONG i = 0; i + patChars <= srcChars; ++i)
        {
            if (RtlEqualMemory(&s[i], p, patChars * sizeof(WCHAR)))
            {
                found = TRUE;
                break;
            }
        }
    }

    RtlFreeUnicodeString(&srcUp);
    RtlFreeUnicodeString(&patUp);
    return found;
}

NTSTATUS RegistryCallback(_In_ PVOID CallbackContext, _In_ PVOID Argument1, _In_ PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackContext);
    NTSTATUS Status = STATUS_SUCCESS;

    UNICODE_STRING RegPath;
    RtlZeroMemory(&RegPath, sizeof(RegPath));
    RegPath.MaximumLength = sizeof(WCHAR) * 0x800;
    RegPath.Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, RegPath.MaximumLength, REG_TAG);
    if (!RegPath.Buffer)
        return Status;

    // Length is already 0 from RtlZeroMemory, but being explicit does no harm.
    RegPath.Length = 0;

    REG_NOTIFY_CLASS NotifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    __try
    {
        switch (NotifyClass)
        {
        case RegNtPreDeleteValueKey:
        {
            PREG_DELETE_VALUE_KEY_INFORMATION pInfo = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
            if (pInfo && pInfo->Object)
            {
                if (GetNameForRegistryObject(&RegPath, pInfo->Object))
                {
                    if (pInfo->ValueName && pInfo->ValueName->Length > 0)
                    {
                        RtlAppendUnicodeToString(&RegPath, L"\\");
                        RtlAppendUnicodeStringToString(&RegPath, pInfo->ValueName);
                    }

                    if (UnicodeContainsInsensitive(&RegPath, REG_PROTECT_SUBPATH) ||
                        UnicodeContainsInsensitive(&RegPath, REG_PROTECT_KEY) ||
                        UnicodeContainsInsensitive(&RegPath, REG_PROTECT_PYAS) ||
                        UnicodeContainsInsensitive(&RegPath, REG_PROTECT_OWLY) ||
                        UnicodeContainsInsensitive(&RegPath, REG_PROTECT_SANCTUM))
                    {
                        // Queue alert (non-blocking)
                        QueueRegistryAlertToUserMode(&RegPath, L"DELETE_VALUE");
                        Status = STATUS_ACCESS_DENIED;
                    }
                }
            }
            break;
        }

        case RegNtPreDeleteKey:
        {
            PREG_DELETE_KEY_INFORMATION pInfo = (PREG_DELETE_KEY_INFORMATION)Argument2;
            if (pInfo && pInfo->Object)
            {
                if (GetNameForRegistryObject(&RegPath, pInfo->Object))
                {
                    if (UnicodeContainsInsensitive(&RegPath, REG_PROTECT_KEY) ||
                        UnicodeContainsInsensitive(&RegPath, REG_PROTECT_PYAS) ||
                        UnicodeContainsInsensitive(&RegPath, REG_PROTECT_OWLY) ||
                        UnicodeContainsInsensitive(&RegPath, REG_PROTECT_SANCTUM))
                    {
                        QueueRegistryAlertToUserMode(&RegPath, L"DELETE_KEY");
                        Status = STATUS_ACCESS_DENIED;
                    }
                }
            }
            break;
        }

        case RegNtPreSetValueKey:
        {
            PREG_SET_VALUE_KEY_INFORMATION pInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
            if (pInfo && pInfo->Object)
            {
                if (GetNameForRegistryObject(&RegPath, pInfo->Object))
                {
                    if (pInfo->ValueName && pInfo->ValueName->Length > 0)
                    {
                        RtlAppendUnicodeToString(&RegPath, L"\\");
                        RtlAppendUnicodeStringToString(&RegPath, pInfo->ValueName);
                    }

                    if (UnicodeContainsInsensitive(&RegPath, REG_PROTECT_SUBPATH) ||
                        UnicodeContainsInsensitive(&RegPath, REG_PROTECT_KEY) ||
                        UnicodeContainsInsensitive(&RegPath, REG_PROTECT_PYAS))
                    {
                        QueueRegistryAlertToUserMode(&RegPath, L"SET_VALUE");
                        Status = STATUS_ACCESS_DENIED;
                    }
                }
            }
            break;
        }

        case RegNtPreRenameKey:
        {
            PREG_RENAME_KEY_INFORMATION pInfo = (PREG_RENAME_KEY_INFORMATION)Argument2;
            if (pInfo && pInfo->Object)
            {
                if (GetNameForRegistryObject(&RegPath, pInfo->Object))
                {
                    if (pInfo->NewName && pInfo->NewName->Length > 0)
                    {
                        RtlAppendUnicodeToString(&RegPath, L"\\");
                        RtlAppendUnicodeStringToString(&RegPath, pInfo->NewName);
                    }

                    if (UnicodeContainsInsensitive(&RegPath, REG_PROTECT_SUBPATH) ||
                        UnicodeContainsInsensitive(&RegPath, REG_PROTECT_KEY) ||
                        UnicodeContainsInsensitive(&RegPath, REG_PROTECT_PYAS))
                    {
                        QueueRegistryAlertToUserMode(&RegPath, L"RENAME_KEY");
                        Status = STATUS_ACCESS_DENIED;
                    }
                }
            }
            break;
        }

        default:
            break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[Registry-Protection] Exception in callback: 0x%X\r\n", GetExceptionCode());
        Status = STATUS_SUCCESS; // Don't propagate exceptions
    }

    ExFreePoolWithTag(RegPath.Buffer, REG_TAG);
    return Status;
}
