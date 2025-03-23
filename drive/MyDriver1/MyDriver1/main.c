#include<ntifs.h>

#define DEVICE_NAME  L"\\Device\\dma"
#define LINK_NAME L"\\DosDevices\\dma"
//#define SYM_NAME L"\\??\\"


#define IO_GetModuleBase          CTL_CODE(FILE_DEVICE_UNKNOWN,0X800,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IO_Read                   CTL_CODE(FILE_DEVICE_UNKNOWN,0X801,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IO_Write                  CTL_CODE(FILE_DEVICE_UNKNOWN,0X802,METHOD_BUFFERED,FILE_ANY_ACCESS)
UNICODE_STRING DeviceName;
PDEVICE_OBJECT DeviceObject;
UNICODE_STRING LineName;

typedef struct _DataST
{
	ULONG pid;
	PVOID Address;
	ULONG Size;
	PVOID Buff;
}DataST, * PDataST;



#pragma pack(4)
typedef struct _PEB32
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	ULONG Ldr;
	ULONG ProcessParameters;
	ULONG SubSystemData;
	ULONG ProcessHeap;
	ULONG FastPebLock;
	ULONG AtlThunkSListPtr;
	ULONG IFEOKey;
	ULONG CrossProcessFlags;
	ULONG UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG ApiSetMap;
} PEB32, * PPEB32;
typedef struct _PEB_LDR_DATA32
{
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;
typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY32 HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;
#pragma pack()

typedef struct _PEB64
{
	UCHAR InheritedAddressSpace;                                            //0x0
	UCHAR ReadImageFileExecOptions;                                         //0x1
	UCHAR BeingDebugged;                                                    //0x2
	union
	{
		UCHAR BitField;                                                     //0x3
		struct
		{
			UCHAR ImageUsesLargePages : 1;                                    //0x3
			UCHAR IsProtectedProcess : 1;                                     //0x3
			UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
			UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
			UCHAR IsPackagedProcess : 1;                                      //0x3
			UCHAR IsAppContainer : 1;                                         //0x3
			UCHAR IsProtectedProcessLight : 1;                                //0x3
			UCHAR IsLongPathAwareProcess : 1;                                 //0x3
		};
	};
	UCHAR Padding0[4];                                                      //0x4
	VOID* Mutant;                                                           //0x8
	VOID* ImageBaseAddress;                                                 //0x10
	VOID* Ldr;                                              //0x18
}PEB64, * PPEB64;

typedef struct _PEB_LDR_DATA64
{
	ULONG Length;
	UCHAR Initialized;
	void* SsHandle;
	LIST_ENTRY InLoadOrderModuleList;             //0x10
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	void* EntryInProgress;
} PEB_LDR_DATA64, * PPEB_LDR_DATA64;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;                                    //0x0
	LIST_ENTRY InMemoryOrderLinks;                                  //0x10
	LIST_ENTRY InInitializationOrderLinks;                          //0x20
	VOID* DllBase;                                                          //0x30 7ff7be310000
	VOID* EntryPoint;                                                       //0x38
	ULONG SizeOfImage;                                                      //0x40
	UNICODE_STRING FullDllName;                                     //0x48
	UNICODE_STRING BaseDllName;                                     //0x58
}LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

NTKERNELAPI PVOID  PsGetProcessWow64Process(PEPROCESS Process);
NTKERNELAPI PVOID  PsGetProcessPeb(PEPROCESS Process);



NTSTATUS QNRead(HANDLE pid, PVOID Address, ULONG Size, PVOID buf)
{
	PEPROCESS Process = NULL;
	KAPC_STATE ApcState = { 0 };
	PMDL mdl = NULL;
	PVOID NEWAress = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(pid, &Process);//��ȡ���̶���ָ��
	
	ObDereferenceObject(Process);//�������ü���
	KeStackAttachProcess(Process,&ApcState);//���̹ҿ�
	mdl = IoAllocateMdl(Address, Size, FALSE, FALSE, NULL); //����mdl�ṹ
	if(!mdl)
	{
		KeUnstackDetachProcess(&ApcState);  //��������ҿ�
		DbgPrintEx(77, 0, "����\n");      //��ӡʧ��
		return STATUS_UNSUCCESSFUL;     //����û�ɹ�
	}
	__try     //��ֹ����
	{
		MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);//�����ڴ�ҳ
	}
	__except (1)
	{
		KeUnstackDetachProcess(&ApcState);  //��������ҿ�
		DbgPrintEx(77, 0, "����\n");      //��ӡʧ��
		IoFreeMdl(mdl); //�ͷ�mdl
		return STATUS_UNSUCCESSFUL;     //����û�ɹ�
	}
	KeUnstackDetachProcess(&ApcState);   //����ҿ�
	NEWAress = MmMapLockedPagesSpecifyCache(mdl,KernelMode,MmCached,NULL,FALSE,HighPagePriority); //ӳ��
	if(!NEWAress)
	{
		MmUnlockPages(mdl);
		IoFreeMdl(mdl); //�ͷ�mdl
		return STATUS_UNSUCCESSFUL;     //����û�ɹ�
	}
	RtlCopyMemory(buf, NEWAress, Size);
	MmUnmapLockedPages(NEWAress,mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);
	return STATUS_SUCCESS;    //���سɹ�
}


NTSTATUS QNWrite(HANDLE pid, PVOID Address, ULONG Size, PVOID buf)
{
	PEPROCESS Process = NULL;
	KAPC_STATE ApcState = { 0 };
	PMDL mdl = NULL;
	PVOID NEWAress = NULL;
	PsLookupProcessByProcessId(pid, &Process);//��ȡ���̶���ָ��
	ObDereferenceObject(Process);//�������ü���
	KeStackAttachProcess(Process, &ApcState);//���̹ҿ�
	mdl = IoAllocateMdl(Address, Size, FALSE, FALSE, NULL); //����mdl�ṹ
	if (!mdl)
	{
		KeUnstackDetachProcess(&ApcState);  //��������ҿ�
		DbgPrintEx(77, 0, "����\n");      //��ӡʧ��
		return STATUS_UNSUCCESSFUL;     //����û�ɹ�
	}
	__try     //��ֹ����
	{
		MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);//�����ڴ�ҳ
	}
	__except (1)
	{
		KeUnstackDetachProcess(&ApcState);  //��������ҿ�
		DbgPrintEx(77, 0, "����\n");      //��ӡʧ��
		IoFreeMdl(mdl); //�ͷ�mdl
		return STATUS_UNSUCCESSFUL;     //����û�ɹ�
	}
	KeUnstackDetachProcess(&ApcState);   //����ҿ�
	NEWAress = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, HighPagePriority); //ӳ��
	if (!NEWAress)
	{
		MmUnlockPages(mdl);
		IoFreeMdl(mdl); //�ͷ�mdl
		return STATUS_UNSUCCESSFUL;     //����û�ɹ�
	}
	RtlCopyMemory(NEWAress, buf, Size);
	MmUnmapLockedPages(NEWAress, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);
	return STATUS_SUCCESS;    //���سɹ�
}

NTSTATUS GetModuleBase(HANDLE pid, char* name , PVOID buf)
{
	PEPROCESS Process = NULL;
	KAPC_STATE ApcState = { 0 };
	PVOID NEWAress = NULL;
	ANSI_STRING Aname = { 0 };
	UNICODE_STRING Uname = {0};
	RtlInitAnsiString(&Aname,name);
	NTSTATUS status = RtlAnsiStringToUnicodeString(&Uname, &Aname, TRUE);
	if (!NT_SUCCESS(status))
	{
		return STATUS_UNSUCCESSFUL;     //����û�ɹ�
	}
	status = PsLookupProcessByProcessId(pid, &Process);//��ȡ���̶���ָ��
	if (!NT_SUCCESS(status))
	{
		return STATUS_UNSUCCESSFUL;     //����û�ɹ�
	}
	ObDereferenceObject(Process);//�������ü���
	BOOLEAN wow64 = PsGetProcessWow64Process(Process); //���Ƿ���32λ
	KeStackAttachProcess(Process, &ApcState);//���̹ҿ�
	if(wow64) //Ϊ32λ
	{
		PPEB32	peb32 = (PPEB32)PsGetProcessWow64Process(Process);
		PPEB_LDR_DATA32 pebldr = (PPEB_LDR_DATA32)peb32->Ldr;
		PLIST_ENTRY32 lisr = &pebldr->InLoadOrderModuleList;
		PLDR_DATA_TABLE_ENTRY32 listnext = (PLDR_DATA_TABLE_ENTRY32)lisr->Flink;
		while(lisr != listnext)
		{
			PWCHAR BASENAME = listnext->BaseDllName.Buffer;
			UNICODE_STRING basename = { 0 };
			RtlInitUnicodeString(&basename,BASENAME);
			if (RtlEqualUnicodeString(&basename, &Uname, TRUE)) //�Ƚ�����
			{
				NEWAress = listnext->DllBase;
			}
			listnext = (PLDR_DATA_TABLE_ENTRY32)listnext->InLoadOrderLinks.Flink;
		}
		KeUnstackDetachProcess(&ApcState);  //��������ҿ�

	}
	else //Ϊ64
	{
		PPEB64	peb32 = (PPEB32)PsGetProcessPeb(Process);
		PPEB_LDR_DATA64 pebldr = (PPEB_LDR_DATA64)peb32->Ldr;
		PLIST_ENTRY lisr = &pebldr->InLoadOrderModuleList;
		PLDR_DATA_TABLE_ENTRY listnext = (PLDR_DATA_TABLE_ENTRY)lisr->Flink;
		while (lisr != listnext)
		{
			PWCHAR BASENAME = listnext->BaseDllName.Buffer;
			UNICODE_STRING basename = { 0 };
			RtlInitUnicodeString(&basename, BASENAME);
			if (RtlEqualUnicodeString(&basename, &Uname, TRUE)) //�Ƚ�����
			{
				NEWAress = listnext->DllBase;
			}
			listnext = (PLDR_DATA_TABLE_ENTRY)listnext->InLoadOrderLinks.Flink;
		}
		KeUnstackDetachProcess(&ApcState);  //��������ҿ�
	}
	RtlCopyMemory(buf, &NEWAress, sizeof(PVOID));
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS IoCreate(PDRIVER_OBJECT DeviceObject,PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS IoControlR3(PDRIVER_OBJECT DeviceObject, PIRP irp)
{
	PIO_STACK_LOCATION  IprStackLocation = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	PDataST R3data = NULL;
	IprStackLocation = IoGetCurrentIrpStackLocation(irp);
	ULONG Size = IprStackLocation->Parameters.DeviceIoControl.InputBufferLength;
	ULONG OutputBuffer = IprStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
	ULONG IoCon = IprStackLocation->Parameters.DeviceIoControl.IoControlCode;

	R3data = irp->AssociatedIrp.SystemBuffer;

	switch(IoCon)
	{
	    case IO_GetModuleBase:
		{
			status = GetModuleBase((HANDLE)R3data->pid, R3data->Address, R3data->Buff);
			break;
		}
		case IO_Read:
		{
			status = QNRead((HANDLE)R3data->pid, R3data->Address, R3data->Size,R3data->Buff);
			break;
		}
		case IO_Write:
		{
			status = QNWrite((HANDLE)R3data->pid, R3data->Address, R3data->Size, R3data->Buff);
			break;
		}
	}
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

VOID UnloadDriver(PDRIVER_OBJECT pDriver)
{
	NTSTATUS status = STATUS_SUCCESS;
	status = IoDeleteSymbolicLink(&LineName);
	if (!NT_SUCCESS(status))
	{
		return STATUS_UNSUCCESSFUL;     //����û�ɹ�
	}
	DbgPrintEx(77, 0, "ɾ���������ӳɹ�\n");
	IoDeleteDevice(DeviceObject);
	DbgPrintEx(77, 0, "ɾ���豸�ɹ�\n");
	DbgPrintEx(77, 0, "����ж�سɹ�\n");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg)
{
	pDriver->MajorFunction[IRP_MJ_CREATE] = IoCreate;
	pDriver->MajorFunction[IRP_MJ_CLOSE] = IoCreate;
	pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControlR3;  //��ǲ����
	pDriver->DriverUnload = UnloadDriver;
	DbgPrintEx(77,0,"�������سɹ�\n");
	//NTSTATUS status = QNRead(7720, 0x16A3D530038, 4, &buf);
	//DbgPrintEx(77,0,"%d\n",buf);
	//NTSTATUS statu = QNWrite(7720, 0x16A3D530038, 4, &buff);
	/*GetModuleBase(7720, "NOTEPAD.EXE", &buf);
	DbgPrintEx(77, 0, "%X\n", buf);*/
	RtlInitUnicodeString(&DeviceName, DEVICE_NAME);
	NTSTATUS status = IoCreateDevice(pDriver,0, &DeviceName,FILE_DEVICE_UNKNOWN,FILE_DEVICE_SECURE_OPEN,FALSE, &DeviceObject);
	if (!NT_SUCCESS(status))
	{
		return STATUS_UNSUCCESSFUL;     //����û�ɹ�
	}
	RtlInitUnicodeString(&LineName, LINK_NAME);
	status = IoCreateSymbolicLink(&LineName, &DeviceName);
	if (!NT_SUCCESS(status))
	{
		return STATUS_UNSUCCESSFUL;     //����û�ɹ�
	}
	return STATUS_SUCCESS;
}