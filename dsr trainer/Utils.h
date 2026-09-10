#pragma once
#include <iostream>
#include <Windows.h>
#include <string>
#include <TlHelp32.h>

namespace Utils {

	class Misc {
	public:
		/// <summary>
		/// compares two wide character arrays until null termination
		/// </summary>
		/// <param name="First">: a pointer to the first character in an array</param>
		/// <param name="Second">: a pointer to the second character in an array</param>
		/// <returns><para>returns true when they are equivalent.</para>
		/// and false when they arent</returns>
		static bool wcharcmp(const WCHAR* First, const WCHAR* Second) {
			while (*First != '\0' && *Second != '\0') {
				if (*First != *Second) return false;
				First += 1;
				Second += 1;
			}
			return true;
		}
	};
	class Processes {

	public:
		/// <summary>
		/// returns a process handle for the specified process with all permissions available
		/// </summary>
		/// <param name="ProcessName">: avoid system processes cuz it might not work in user-level</param>
		/// <returns><para>HANDLE to process if Succesful</para>nullptr if snapshot failed</returns>
		static HANDLE GetProcessHandleAllPerms(const WCHAR* ProcessName) {
			DWORD PID = 0;
			HANDLE Hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			PROCESSENTRY32 p32;
			p32.dwSize = sizeof(PROCESSENTRY32);

			if (!Process32First(Hsnap, &p32)) { std::cerr << "creating snapshot failed\n"; return nullptr; } // if returned nullptr, then snapshot has failed
			do {
				if (Misc::wcharcmp(p32.szExeFile, ProcessName)) {
					PID = p32.th32ProcessID;
					break;
				}
			} while (Process32Next(Hsnap, &p32)); // searching for process

			if (PID == 0) { std::cerr << "\033[31m" << "Process not found\n" << "\033[0m"; return nullptr; }
			HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, false, PID);
			DWORD err = GetLastError();
			switch (err) {
			case ERROR_ACCESS_DENIED:
				std::cerr << "\033[31m" << "Access Denied vro. consider using a process that is not protected\n" << "\033[0m";
				break;
			case ERROR_INVALID_PARAMETER:
				std::cerr << "\033[31m" << "System Idle was Passed. this might be because (my checks failed && (snapshot failed || your process not found))\n" << "\033[0m";
				break;
			}
			return handle;
		}
	};
}