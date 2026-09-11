#pragma once
#include <iostream>
#include <Windows.h>
#include <string>
#include <TlHelp32.h>

// error handling looks atrocious. ill DRY it tomorrow

namespace Utils {

	namespace Misc {

		namespace Colors {
			inline const std::string_view red = "\033[31m";
			inline const std::string_view reset = "\033[0m";
		}
		class Methods {
		public:
			/// <summary>
			/// compares two wide character arrays until null termination
			/// </summary>
			/// <param name="First">: a pointer to the first character in an array</param>
			/// <param name="Second">: a pointer to the second character in an array</param>
			/// <returns><para>returns true when they are equivalent.</para>
			/// and false when they arent</returns>
			static inline bool wcharcmp(const WCHAR* First, const WCHAR* Second) {
				while (*First != '\0' && *Second != '\0') {
					if (*First != *Second) return false;
					First += 1;
					Second += 1;
				}
				return true;
			}
			/// <summary>
			/// converts a wide character array to an std::string
			/// </summary>
			/// <param name="wchar">: a pointer to the first character in the array</param>
			/// <returns>returns std::string that contains characters from <paramref name="wchar"/> array</returns>
			static inline std::string wchartostr(const WCHAR* wchar) {
				if (wchar) {
					std::string buffer;
					while (*wchar != '\0') {
						buffer += *wchar;
						wchar += 1;
					}
					return buffer;
				}
				return "";
			}
		};
	}



	class Processes {
	

	public:
		struct stInjection {
			bool success = false;
			size_t threadID = 0;
		};


		/// <summary>
		/// returns a process handle for the specified process with all permissions available
		/// </summary>
		/// <param name="ProcessName"><para>: a wide character array that has process name.</para>avoid system processes cuz it might not work in user-level</param>
		/// <returns><para>HANDLE to process if Succesful</para>nullptr if snapshot failed</returns>
		static inline HANDLE GetProcessHandleAllPerms(const WCHAR* ProcessName) {
			if (ProcessName == nullptr) {
				std::cerr
					<< Misc::Colors::red
					<< "Invalid parameter to GetProcessHandleAllPerms. cant take nullptr as a parameter\n"
					<< Misc::Colors::reset;
				return nullptr;
			}
			DWORD PID = 0;
			HANDLE Hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			PROCESSENTRY32 p32;
			p32.dwSize = sizeof(PROCESSENTRY32);

			if (!Process32First(Hsnap, &p32)) { std::cerr << "creating snapshot failed\n"; return nullptr; } // snapshot failling indicated that you might not have sufficient permissions. 
			do {
				if (Misc::Methods::wcharcmp(p32.szExeFile, ProcessName)) {
					PID = p32.th32ProcessID;
					break;
				}
			} while (Process32Next(Hsnap, &p32));
			if (PID == 0) { std::cerr << "\033[31m" << "Process not found\n" << "\033[0m"; return nullptr; }
			
			HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, false, PID);

			DWORD err = GetLastError();
			switch (err) {
			case ERROR_ACCESS_DENIED:
				std::cerr 
					<< Misc::Colors::red 
					<< "Error while trying to get process handle for "
					<< Misc::Methods::wchartostr(p32.szExeFile)
					<< "\nPID: " 
					<< p32.th32ProcessID
					<< "\nError code: "
					<< err
					<< "\nExplanation: ACCESS DENIED. you might've tried to access a system process or a protected one\n"
					<< Misc::Colors::reset;
				break;

			case ERROR_INVALID_PARAMETER:
				std::cerr 
					<< Misc::Colors::red 
					<< "Error while trying to get process handle for "
					<< Misc::Methods::wchartostr(p32.szExeFile)
					<< "\nPID: "
					<< p32.th32ProcessID
					<< "\nError code: "
					<< err
					<< "\nExplanation: INVALID PARAMETER. you might've tried to access \"System Idle\" process or passed nullptr\n"
					<< Misc::Colors::reset;
				break;
			}
			return handle;
		}

		/// <summary>
		/// Injects code into another process to allow functionality of choice
		/// </summary>
		/// <param name="Hprocess">: a handle to the target process</param>
		/// <param name="DLLpath">: path to the dll that will be injected</param>
		/// <param name="size">: an integer specifying how many bytes to copy from buffer and inject into process</param>
		/// <returns>a struct housing injection status, and a pointer to injected bytes in memory</returns>
		static inline stInjection InjectIntoProcess(HANDLE& Hprocess, std::string dllpath) {
			stInjection status;
			if (!Hprocess || dllpath == "")
			{
				std::cerr
					<< Misc::Colors::red
					<< "Invalid parameters to InjectIntoProcess\n"
					<< Misc::Colors::reset;
				return status;
			}

			size_t dllLen = dllpath.length() + 1;
			void* LPdllName = VirtualAllocEx(Hprocess,
				NULL,
				dllLen,
				MEM_COMMIT | MEM_RESERVE,
				PAGE_READWRITE);
			if (!LPdllName) {
				std::cerr
					<< Misc::Colors::red
					<< "Error while trying to allocate memory into remote process\n"
					<< "Error code: "
					<< GetLastError()
					<< "\n"
					<< Misc::Colors::reset;
				return status;
			}

			if (!WriteProcessMemory(Hprocess, LPdllName, dllpath.c_str(), dllLen, nullptr)) {
				std::cerr
					<< Misc::Colors::red
					<< "Error while trying to write into process memory.\n"
					<< "Error code: "
					<< GetLastError()
					<< "\n"
					<< Misc::Colors::reset;
				VirtualFreeEx(Hprocess, LPdllName, 0, MEM_RELEASE);
				return status;
			}

			HMODULE HMkernel = GetModuleHandleA("kernel32.dll");
			if (!HMkernel)
			{
				std::cerr
					<< Misc::Colors::red
					<< "Error while trying to get a module handle to kernel32.dll\n"
					<< "Error code: "
					<< GetLastError()
					<< "\n"
					<< Misc::Colors::reset;
				VirtualFreeEx(Hprocess, LPdllName, 0, MEM_RELEASE);
				return status;
			}

			LPTHREAD_START_ROUTINE LLaddress = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(HMkernel, "LoadLibraryA"));
			if (!LLaddress) 
			{
				std::cerr
					<< Misc::Colors::red
					<< "Error while trying to get procedure LoadLibraryA address from memory\n"
					<< "Error code: "
					<< GetLastError()
					<< "\n"
					<< Misc::Colors::reset;
				VirtualFreeEx(Hprocess, LPdllName, 0, MEM_RELEASE);
				return status;
			}

			uint32_t threadID = 0;
			if (!CreateRemoteThread(Hprocess, NULL, 0, LLaddress, LPdllName, 0, reinterpret_cast<DWORD*>(threadID)))
			{
				std::cerr
					<< Misc::Colors::red
					<< "Error while trying to create remote thread\n"
					<< "Error code: "
					<< GetLastError()
					<< "\n"
					<< Misc::Colors::reset;
				VirtualFreeEx(Hprocess, LPdllName, 0, MEM_RELEASE);
				return status;
			}

			status.success = true;
			status.threadID = threadID;
			return status;
		}
	};
}