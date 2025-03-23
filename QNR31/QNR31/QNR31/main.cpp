#include <Windows.h>
#include <stdio.h>
#define LINE_NAME "\\\\.\\dma"
#define IO_GetModuleBase          CTL_CODE(FILE_DEVICE_UNKNOWN,0X800,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IO_Read                   CTL_CODE(FILE_DEVICE_UNKNOWN,0X801,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IO_Write                  CTL_CODE(FILE_DEVICE_UNKNOWN,0X802,METHOD_BUFFERED,FILE_ANY_ACCESS)
HANDLE Hdece;

typedef struct _DataST
{
	ULONG pid;
	ULONG64 Address;
	ULONG Size;
	ULONG64 Buff;
}DataST, * PDataST;

BOOL GetModuleBase(ULONG PID,PCHAR Name, ULONG64 *buff)
{
	DataST data;
	data.pid = PID;
	data.Address = (ULONG64)Name;
	data.Size = strlen(Name);
	data.Buff = (ULONG64)buff;
	DWORD dwRet = 0;
	BOOL R3TX = DeviceIoControl(Hdece, IO_GetModuleBase,&data,sizeof(data),NULL,0, &dwRet,0);
	if (R3TX == FALSE)
	{
		return FALSE;
	}
	return TRUE;
}

BOOL QNRead(ULONG PID, ULONG64 address, ULONG size,ULONG64* buff)
{
	DataST data;
	data.pid = PID;
	data.Address = address;
	data.Size = size;
	data.Buff = (ULONG64)buff;
	DWORD dwRet = 0;
	BOOL R3TX = DeviceIoControl(Hdece, IO_Read, &data, sizeof(data), NULL, 0, &dwRet, 0);
	if (R3TX == FALSE)
	{
		return FALSE;
	}
	return TRUE;
}

BOOL QNWrite(ULONG PID, ULONG64 address, ULONG size, ULONG64* buff)
{
	DataST data;
	data.pid = PID;
	data.Address = address;
	data.Size = size;
	data.Buff = (ULONG64)buff;
	DWORD dwRet = 0;
	BOOL R3TX = DeviceIoControl(Hdece, IO_Write, &data, sizeof(data), NULL, 0, &dwRet, 0);
	if (R3TX == FALSE)
	{
		return FALSE;
	}
	return TRUE;
}

int main()
{
	ULONG PID = 7204;
	ULONG64 Add = NULL;
	ULONG64 Bdd = 10;
	ULONG64 Cdd = NULL;
	Hdece = CreateFileA(LINE_NAME,GENERIC_READ|GENERIC_WRITE,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_SYSTEM,0);
	if (Hdece == INVALID_HANDLE_VALUE)
	{
		printf("设备打开失败\n");
		return 0;
	}
	printf("设备打开成功\n");
	GetModuleBase(PID, (PCHAR)"NOTEPAD.EXE", &Add);
	printf("base:[0x%016llX]\n", Add);
	QNRead(PID,0x1FEB08C0130, 4, &Cdd);
	printf("data:%d\n", Cdd);
	QNWrite(PID,0x1FEB08C0130, 4, &Bdd);
	CloseHandle(Hdece);
	system("pause");
	return 0;
}