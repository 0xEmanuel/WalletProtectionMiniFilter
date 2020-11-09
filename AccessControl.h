#pragma once
//test
#include "Utils.h"
#include "Helpers.h"

#define NUM_WALLET_CLIENT_ENTRIES 3
#define NUM_SLOTS 4
#define NUM_PROTECTED_WALLETS 33

#define GetFreeSlotInWhitelist() IdentifyProcess(0, NULL)
#define RemoveProcessFromWhitelist(slot) SetProcessInWhitelist(slot, 0, NULL)


//Hardcoded, since its just a Proof of concept
static CONST CHAR* imageNameWhistelist[NUM_WALLET_CLIENT_ENTRIES] =
{
	"bitcoin-qt.exe",
	"electrum-3.2.2",
	"notepad.exe" //allows multiple processes, this is just for tests here
};

static CONST CHAR* sha256Whitelist[NUM_WALLET_CLIENT_ENTRIES] =
{
	"988970438f041b99ec4b6f2fc894e2de3e4bbdc4baac4dda1701f1993a8e40e7",
	"fc380c59b07b290c20b7d87860841b440d633abcc129d6b1bf4a4ad069684270",
	"e9f2fbe8e1bc49d107df36ef09f6d0aeb8901516980d3fe08ee73ab7b4a2325f" //notepad.exe in win10test VM
};

//Future work: the user should actually have the option to set the to be protected paths on his own.
static CONST WCHAR* PROTECTED_WALLETS[NUM_PROTECTED_WALLETS] =
{
	L"\\Device\\HarddiskVolume2\\Users\\WDKRemoteUser\\Desktop\\wallet.dat",
	L"\\Device\\HarddiskVolume2\\Users\\WDKRemoteUser\\AppData\\Roaming\\Electrum\\wallets\\default_wallet",

	L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\Roaming\\Bitcoin\\wallets\\wallet.dat",
	L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\Roaming\\Bitcoin\\wallet.dat",
	L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\Roaming\\Bitcoinwallet.dat",

	L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\Local\\Bitcoin\\wallets\\wallet.dat",
	L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\Local\\Bitcoin\\wallet.dat",
	L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\Local\\Bitcoinwallet.dat",

	L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\Local\\Electrum\\wallets\\default_wallet",
	L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\Local\\Electrum\\wallets\\wallet_1",
	L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\Local\\Electrum\\wallets\\electrum.dat",
	L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\Local\\Electrum\\default_wallet",
	L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\Local\\Electrum\\wallet_1",
	L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\Local\\Electrum\\electrum.dat",

	L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\Roaming\\Electrum\\wallets\\default_wallet",
	L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\Roaming\\Electrum\\wallets\\wallet_1",
	L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\Roaming\\Electrum\\wallets\\electrum.dat",
	L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\Roaming\\Electrum\\default_wallet",
	L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\Roaming\\Electrum\\wallet_1",
	L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\Roaming\\Electrum\\electrum.dat",

	L"\\Device\\HarddiskVolume2\\Users\\user\\Downloads\\electrum_data\\wallets\\default_wallet",
	L"\\Device\\HarddiskVolume2\\Users\\user\\Downloads\\electrum_data\\wallets\\wallet_1",
	L"\\Device\\HarddiskVolume2\\Users\\user\\Downloads\\electrum_data\\wallets\\electrum.dat",
	L"\\Device\\HarddiskVolume2\\Users\\user\\Downloads\\electrum_data\\default_wallet",
	L"\\Device\\HarddiskVolume2\\Users\\user\\Downloads\\electrum_data\\wallet_1",
	L"\\Device\\HarddiskVolume2\\Users\\user\\Downloads\\electrum_data\\electrum.dat",

	L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\Roaming\\Armory\\armory_za4XpjQB_.wallet",
	L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\Roaming\\Armory\\armory_za4XpjQB_backup.wallet",
	L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\Roaming\\Parity\\Ethereum\\keys\\ethereum\\UTC--2018-10-24T14-42-47Z--91ea0b0d-899f-54a6-7379-c532d9daf947",
	L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\Roaming\\Exodus\\exodus.wallet\\passphrase.json",
	L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\Roaming\\Exodus\\exodus.wallet\\seed.seco",
	L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\Roaming\\MultiBitHD\\mbhd-b4ebd36b-ed281c60-fcfc97a1-6d11a6b9-2163e344\\mbhd.wallet.aes",
	L"\\Device\\HarddiskVolume2\\Users\\user\\Documents\\Monero\\wallets\\user\\user.keys"
};

//unsorted process whitelist
static ULONG pidWhitelist[NUM_SLOTS] = { 0 };
static ULONG processPtrWhitelist[NUM_SLOTS] = { 0 };

VOID DenyFileAccess(PFLT_CALLBACK_DATA data);
BOOLEAN IsLegitProcess(PFLT_CALLBACK_DATA data);
BOOLEAN IsWallet(WCHAR *filename);

INT IdentifyImageName(CHAR* imageName);
INT IdentifyProcess(ULONG pid, PEPROCESS pProcess);

VOID SetProcessInWhitelist(INT slot, ULONG pid, PEPROCESS pProcess);

BOOLEAN IsHashValid(CHAR* hashStr, INT imageId);

VOID ProcessNotifyRoutine(HANDLE hParentId, HANDLE hProcessId, BOOLEAN isCreateProcess);

extern CHAR* PsGetProcessImageFileName(PEPROCESS pProcess);