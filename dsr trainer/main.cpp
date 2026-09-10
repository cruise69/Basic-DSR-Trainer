#include <iostream>
#include <Windows.h>
#include "Utils.h"

int main(int argc, char* argv) {
	HANDLE proc = Utils::Processes::GetProcessHandleAllPerms(L"smss.exe");
	std::cout << "PID: " << GetProcessId(proc) << std::endl;
	return 0;
}