#include "AccessControl.h"

VOID DenyFileAccess(PFLT_CALLBACK_DATA data)
{
	data->IoStatus.Status = STATUS_ACCESS_DENIED;
	data->IoStatus.Information = 0; //transfering size		
}

//Future work: Actually needs also to check integrity of all modules (dll's) that are related to the process.
BOOLEAN IsLegitProcess(PFLT_CALLBACK_DATA data)
{
	ULONG processId = FltGetRequestorProcessId(data);
	Log("processId: %lu", processId);

	PEPROCESS pProcess = FltGetRequestorProcess(data); //this function extracts the process pointer from data
	if (pProcess == NULL)
		return FALSE;

	//--------------------------------------------------------------------------------
	Log("State of whitelist:", processId);
	PrintArray(pidWhitelist, sizeof(pidWhitelist) / sizeof(pidWhitelist[0]));
	PrintArray(processPtrWhitelist, sizeof(processPtrWhitelist) / sizeof(processPtrWhitelist[0]));

	if (IdentifyProcess(processId, pProcess) != -1)
		return TRUE;

	//--------------------------------------------------------------------------------
	//Check process
	CHAR* imageName = (CHAR*)PsGetProcessImageFileName(pProcess); //this returns the imageName from the EPROCESS struct, thus the returned pointer points directly into the EPROCESS struct.
	Log("imageName: %s", imageName);

	INT imageId = IdentifyImageName(imageName);
	if (imageId == -1)
		return FALSE;

	//--------------------------------------------------------------------------------
	//Verify image of process
	WCHAR imagePath[MAXIMUM_FILENAME_LENGTH] = { 0 };
	GetProcessImagePath(pProcess, imagePath);
	Log("imagePath: %ws", imagePath);

	CHAR sha256buf[65] = { 0 }; //SHA256 (32 Bytes) -> 64 HexDigits + NUL terminator = 65 bytes to allocate
	NTSTATUS status = CalcHash(BCRYPT_SHA256_ALGORITHM, imagePath, sizeof(sha256buf), sha256buf);

	if (!NT_SUCCESS(status))
	{
		Log("Failed - status: %x", status);
		return FALSE;
	}
	Log("Sha256: %s", sha256buf);

	if (!IsHashValid(sha256buf, imageId))
		return FALSE;

	INT slot = GetFreeSlotInWhitelist();
	if (slot == -1)
	{
		Log("No free slots in process whitelist!");
		return FALSE;
	}
		
	SetProcessInWhitelist(slot, processId, pProcess);
	Log("Set %lu at slot %d in whitelist:", processId, slot);
	PrintArray(pidWhitelist, sizeof(pidWhitelist) / sizeof(pidWhitelist[0]));
	PrintArray(processPtrWhitelist, sizeof(processPtrWhitelist) / sizeof(processPtrWhitelist[0]));

	return TRUE;
}

BOOLEAN IsWallet(WCHAR *filename)
{
	if (FindStringInArrayW(filename, PROTECTED_WALLETS, sizeof(PROTECTED_WALLETS) / sizeof(PROTECTED_WALLETS[0])) == -1)
		return FALSE;

	return TRUE;
}

/*
* If WalletClient identified, it returns its ID
* returns -1 if WalletClient not identified
*/
INT IdentifyImageName(CHAR* imageName)
{
	return FindStringInArrayA(imageName, imageNameWhistelist, (sizeof(imageNameWhistelist) / sizeof(imageNameWhistelist[0])));
}


/*
* Lookup process in the process whitelists and return position of the first matching process
*/
INT IdentifyProcess(ULONG pid, PEPROCESS pProcess)
{
	ULONG processPtr = PtrToUlong(pProcess);

	for (DWORD i = 0; i < NUM_SLOTS; i++)
		if ( (pidWhitelist[i] == pid) && (processPtrWhitelist[i] == processPtr))
			return i;
	return -1;
}

/*
* Set process in whitelist in specified slot
*/
VOID SetProcessInWhitelist(INT slot, ULONG pid, PEPROCESS pProcess)
{
	pidWhitelist[slot] = pid;

	ULONG processPtr = PtrToUlong(pProcess);
	processPtrWhitelist[slot] = processPtr;
}


BOOLEAN IsHashValid(CHAR* hashStr, INT imageId)
{
	if (imageId == -1) //imageId must be valid
		return FALSE;

	BOOLEAN hashIsValid = FALSE;
	if (strcmp(hashStr, sha256Whitelist[imageId]) == 0)
		hashIsValid = TRUE;

	return hashIsValid;
}


VOID ProcessNotifyRoutine(HANDLE hParentId, HANDLE hProcessId, BOOLEAN isCreateProcess) //hProcessId is really the process id
{
	UNREFERENCED_PARAMETER(hParentId);
	
	if (isCreateProcess)
		return; // we are only interested in terminating processes

	PEPROCESS pProcess;
	NTSTATUS status = PsLookupProcessByProcessId(hProcessId, &pProcess); // increases reference count on object
	if (!NT_SUCCESS(status))
		return;

	ULONG processId = HandleToUlong(hProcessId);
	INT slot = IdentifyProcess(processId, pProcess);

	if (slot != -1)
	{
		Log("%lu terminated. Remove from whitelist:", processId);
		RemoveProcessFromWhitelist(slot);

		PrintArray(pidWhitelist, sizeof(pidWhitelist) / sizeof(pidWhitelist[0]));
		PrintArray(processPtrWhitelist, sizeof(processPtrWhitelist) / sizeof(processPtrWhitelist[0]));
	}

	ObDereferenceObjectDeferDelete(pProcess); //decrease reference count of object
}