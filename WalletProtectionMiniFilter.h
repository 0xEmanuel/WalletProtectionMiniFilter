#pragma
#include "WPP.h"
#include "Utils.h"
#include "Helpers.h"
#include "AccessControl.h"
#include "WalletProtectionMiniFilter.tmh" 

PFLT_FILTER FilterHandle = NULL;
DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverUnload(FLT_FILTER_UNLOAD_FLAGS flags);
FLT_PREOP_CALLBACK_STATUS PreCreate(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS fltObjects, PVOID* completionContext);

PDRIVER_OBJECT g_DriverObject = NULL;