#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <shlwapi.h>
#pragma comment(lib,"Shlwapi.lib")

/*
	原理：通过 DuplicateHandle 关闭 wechat.exe 里的互斥对象
*/

/*
BOOL DuplicateHandle(
HANDLE hSourceProcessHandle,	// 来源进程（从XX复制 ） 也就是 OpenProcess 的返回值
HANDLE hSourceHandle,			// 来源进程内的 X句柄
HANDLE hTargetProcessHandle,	// 目标进程（复制到 ） 
LPHANDLE lpTargetHandle,		// 接收X句柄的地址指针
DWORD dwDesiredAccess,			// 设置复制来的句柄的 访问权限
BOOL bInheritHandle,			// 设置复制来的句柄   继承属性
DWORD dwOptions					// 其他选项（0x1 DUPLICATE_CLOSE_SOURCE 0x2 DUPLICATE_SAME_ACCESS）
								// 写 DUPLICATE_SAME_ACCESS 的话，dwDesiredAccess 就忽略了
);
*/
 
#define NT_SUCCESS(Status)((NTSTATUS)(Status)>=0)
#define STATUS_SUCCESS 0x00000000
#define STATUS_UNSUCCESSFUL 0xC0000001
#define STATUS_NOT_IMPLEMENTED 0xC0000002
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define STATUS_INVALID_PARAMETER 0xC000000D
#define STATUS_ACCESS_DENIED 0xC0000022
#define STATUS_BUFFER_TOO_SMALL 0xC0000023
#define OBJ_KERNEL_HANDLE 0x00000200

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,              // 0        Y        N
	SystemProcessorInformation,          // 1        Y        N
	SystemPerformanceInformation,        // 2        Y        N
	SystemTimeOfDayInformation,          // 3        Y        N
	SystemNotImplemented1,               // 4        Y        N
	SystemProcessesAndThreadsInformation, // 5       Y        N
	SystemCallCounts,                    // 6        Y        N
	SystemConfigurationInformation,      // 7        Y        N
	SystemProcessorTimes,                // 8        Y        N
	SystemGlobalFlag,                    // 9        Y        Y
	SystemNotImplemented2,               // 10       Y        N
	SystemModuleInformation,             // 11       Y        N
	SystemLockInformation,               // 12       Y        N
	SystemNotImplemented3,               // 13       Y        N
	SystemNotImplemented4,               // 14       Y        N
	SystemNotImplemented5,               // 15       Y        N
	SystemHandleInformation,             // 16       Y        N
	SystemObjectInformation,             // 17       Y        N
	SystemPagefileInformation,           // 18       Y        N
	SystemInstructionEmulationCounts,    // 19       Y        N
	SystemInvalidInfoClass1,             // 20
	SystemCacheInformation,              // 21       Y        Y
	SystemPoolTagInformation,            // 22       Y        N
	SystemProcessorStatistics,           // 23       Y        N
	SystemDpcInformation,                // 24       Y        Y
	SystemNotImplemented6,               // 25       Y        N
	SystemLoadImage,                     // 26       N        Y
	SystemUnloadImage,                   // 27       N        Y
	SystemTimeAdjustment,                // 28       Y        Y
	SystemNotImplemented7,               // 29       Y        N
	SystemNotImplemented8,               // 30       Y        N
	SystemNotImplemented9,               // 31       Y        N
	SystemCrashDumpInformation,          // 32       Y        N
	SystemExceptionInformation,          // 33       Y        N
	SystemCrashDumpStateInformation,     // 34       Y        Y/N
	SystemKernelDebuggerInformation,     // 35       Y        N
	SystemContextSwitchInformation,      // 36       Y        N
	SystemRegistryQuotaInformation,      // 37       Y        Y
	SystemLoadAndCallImage,              // 38       N        Y
	SystemPrioritySeparation,            // 39       N        Y
	SystemNotImplemented10,              // 40       Y        N
	SystemNotImplemented11,              // 41       Y        N
	SystemInvalidInfoClass2,             // 42
	SystemInvalidInfoClass3,             // 43
	SystemTimeZoneInformation,           // 44       Y        N
	SystemLookasideInformation,          // 45       Y        N
	SystemSetTimeSlipEvent,              // 46       N        Y
	SystemCreateSession,                 // 47       N        Y
	SystemDeleteSession,                 // 48       N        Y
	SystemInvalidInfoClass4,             // 49
	SystemRangeStartInformation,         // 50       Y        N
	SystemVerifierInformation,           // 51       Y        Y
	SystemAddVerifier,                   // 52       N        Y
	SystemSessionProcessesInformation    // 53       Y        N
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS ( WINAPI *_ZwQuerySystemInformation) (
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength);

typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllInformation,
	ObjectDataInformation,
} OBJECT_INFORMATION_CLASS;
typedef NTSTATUS(NTAPI *NTQUERYOBJECT)(
	HANDLE Handle,
	OBJECT_INFORMATION_CLASS ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);
typedef struct _UNICODE_STRING {
	USHORT  Length;     //UNICODE占用的内存字节数，个数*2；
	USHORT  MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef struct _OBJECT_NAME_INFORMATION {
	UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;
typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG ProcessId;
	UCHAR ObjectTypeNumber;
	UCHAR Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
}SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_INFORMATION Information[1];
}SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

void EnumObjInfo(LPVOID pBuffer, DWORD pid);
NTQUERYOBJECT    NtQueryObject;
_ZwQuerySystemInformation ZwQuerySystemInformation;
bool EnableDebugPrivilege();


PVOID GetObjBuffer()
{
	ULONG dwNeedSize = 0;
	PVOID pBuff = NULL;
	ULONG dwSize = 4096;

	ZwQuerySystemInformation = (_ZwQuerySystemInformation)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "ZwQuerySystemInformation");
	NtQueryObject = (NTQUERYOBJECT)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQueryObject");

	printf("%d\n",EnableDebugPrivilege());

	pBuff = malloc(dwSize);
	do {
		NTSTATUS status = ZwQuerySystemInformation(SystemHandleInformation, pBuff, dwSize, &dwNeedSize);
		if (status == STATUS_INFO_LENGTH_MISMATCH )
		{
			free (pBuff);
			dwSize <<= 1;

		}
		else if (status == STATUS_SUCCESS)
		{
			break;
		}
		pBuff = malloc(dwSize);

	}while(1);

	return pBuff;
}

int main(int argc, char* argv[])
{
	if (argc == 2)
	{
		PVOID pObjInfo = GetObjBuffer();
		if (pObjInfo)
		{
			EnumObjInfo(pObjInfo,atoi((char*)argv[1]));
			free(pObjInfo);
		}

	}
	else
	{
		printf("\nusage %s wechat.exe PID\n",argv[0]);
	}

	return 0;
}

void EnumObjInfo(LPVOID pBuffer, DWORD pid)
{
	char szType[128] = { 0 };
	char szName[512] = { 0 };
	DWORD dwFlags = 0;

	POBJECT_NAME_INFORMATION pNameInfo;
	POBJECT_NAME_INFORMATION pNameType;

	PSYSTEM_HANDLE_INFORMATION_EX pInfo = (PSYSTEM_HANDLE_INFORMATION_EX)pBuffer;
	ULONG OldPID = 0;
	for (DWORD i = 0; i < pInfo->NumberOfHandles; i++)
	{
		if (OldPID != pInfo->Information[i].ProcessId)
		{
			if (pInfo->Information[i].ProcessId == pid)
			{
				HANDLE newHandle;
				DuplicateHandle(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pInfo->Information[i].ProcessId), (HANDLE)pInfo->Information[i].Handle, GetCurrentProcess(), &newHandle, DUPLICATE_SAME_ACCESS, FALSE, DUPLICATE_SAME_ACCESS);
				NTSTATUS status1 = NtQueryObject(newHandle, ObjectNameInformation, szName, 512, &dwFlags);
				NTSTATUS status2 = NtQueryObject(newHandle, ObjectTypeInformation, szType, 128, &dwFlags);
				if (strcmp(szName, "") && strcmp(szType, "") && status1 != 0xc0000008 && status2 != 0xc0000008)
				{
					pNameInfo = (POBJECT_NAME_INFORMATION)szName;
					pNameType = (POBJECT_NAME_INFORMATION)szType;
					
					// printf("%wZ   ", pNameType);
					// printf("%wZ \n", pNameInfo);

					// WeChat_App_Instance_Identity_Mutex_Name
					if (StrStrW(pNameInfo->Name.Buffer,L"WeChat_App_Instance_Identity_Mutex_Name"))
					{
						// 复制后关闭源句柄
						BOOL dupOK = DuplicateHandle(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pInfo->Information[i].ProcessId),(HANDLE)pInfo->Information[i].Handle,GetCurrentProcess(), &newHandle, DUPLICATE_SAME_ACCESS,FALSE,DUPLICATE_CLOSE_SOURCE);
						
						printf("多开成功!\n");
						
						// printf("多开 %d %wZ \n", dupOK, pNameInfo);
						 CloseHandle(newHandle);
					}
				}
			}
		}
	}
}
bool EnableDebugPrivilege()
{
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		return   false;
	}
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))
	{
		CloseHandle(hToken);
		return false;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))
	{
		CloseHandle(hToken);
		return false;
	}
	return true;
}
