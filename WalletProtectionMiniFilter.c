/*
WalletFileProtection
Author: Emanuel Durmaz
*/

#include "WalletProtectionMiniFilter.h" 


/*++

Module Name:

    WalletProtectionMiniFilter.c

Abstract:

    This is the main module of the WalletProtectionMiniFilter miniFilter driver.

Environment:

    Kernel mode

--*/


/*
Using following dependencies:
fltmgr.lib
cng.lib

*/

/*
Changes to the Project

Change Platform to x64
C/C++: Warning Level to Level1
Linker: Treat Linker Warning As Errors: No
Driver Settings Target OS Version: Windows10

*/



CONST FLT_OPERATION_REGISTRATION Callbacks[] =
{
	{ IRP_MJ_CREATE,0,PreCreate,NULL }, // register a PreOperation callback for Create / Open. PostOperation not needed.
	{ IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration =
{
	sizeof(FLT_REGISTRATION),
	FLT_REGISTRATION_VERSION,
	FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, //With this flag the minifilter will not call the pre and post ops for paging io operations
	NULL,
	Callbacks, //register our callbacks
	DriverUnload, //register unload function
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};


_Use_decl_annotations_ NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
	WPP_SYSTEMCONTROL(driverObject); // include this macro to support Win2K.
	WPP_INIT_TRACING(driverObject, registryPath);
	g_DriverObject = driverObject;

	Log("DriverEntry");

	// use .reload in windbg terminal to load symbols for first debug run

	//We need this function later
	if (NULL == ZwQueryInformationProcess)
	{
		UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");
		ZwQueryInformationProcess = (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);

		if (NULL == ZwQueryInformationProcess)
		{
			Log("Cannot resolve ZwQueryInformationProcess");
			return STATUS_NOT_FOUND;
		}
	}

	//register to the filter manager
	NTSTATUS status = FltRegisterFilter(driverObject, &FilterRegistration, &FilterHandle);

	if (NT_SUCCESS(status))
	{
		status = FltStartFiltering(FilterHandle);
		//if filtering doesnt start, unregister our filter
		if (!NT_SUCCESS(status))
		{
			FltUnregisterFilter(FilterHandle);
			return status;
		}		
	}

	//register a callback to get a notifcation about process termination (and creation)
	status = PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)ProcessNotifyRoutine, FALSE);

	if (!NT_SUCCESS(status))
		FltUnregisterFilter(FilterHandle);

	return status;
}

NTSTATUS DriverUnload(FLT_FILTER_UNLOAD_FLAGS flags)
{
	UNREFERENCED_PARAMETER(flags);
	Log("DriverUnload");

	//unregister filter / callbacks
	FltUnregisterFilter(FilterHandle);
	NTSTATUS status = PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)ProcessNotifyRoutine, TRUE);

	WPP_CLEANUP(g_DriverObject);
	return status;
}


FLT_PREOP_CALLBACK_STATUS PreCreate(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS fltObjects, PVOID* completionContext)
{
	UNREFERENCED_PARAMETER(fltObjects);
	UNREFERENCED_PARAMETER(completionContext);
	

	WCHAR filePath[MAXIMUM_FILENAME_LENGTH] = {0};
	NTSTATUS status = ExtractFilePath(data, filePath);

	
	if (NT_SUCCESS(status) && IsWallet(filePath))
	{
		Log("--------Start Wallet Access Check--------");
		Log("Wallet Path: %ls", filePath);
		if (!IsLegitProcess(data))
		{
			DenyFileAccess(data);
			Log("--------Process not legit. Access denied!--------");

			/*	
			The minifilter driver is completing the I/O operation.
			The filter manager does not send the I/O operation to any minifilter drivers below the caller in the driver stack or to the file system.
			In this case, the filter manager only calls the post-operation callback routines of the minifilter drivers above the caller in the driver stack. 
			*/
			return FLT_PREOP_COMPLETE;
		}
		Log("--------Process legit. Access approved!--------");
	}		
	
	/*
	The minifilter driver is returning the I/O operation to the filter manager for further processing.
	In this case, the filter manager does not call the minifilter driver's post-operation callback, if one exists, during I/O completion.
	*/
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}