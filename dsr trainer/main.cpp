#include <iostream>
#include <Windows.h>
#include "Utils.h"

// whatever you might wanna look at in this commit which no ones gonna care about. hear me out
// things might look too generic or random around here cuz its just for testing at the moment
// and im not so good of a software developer (yet) to do proper testing, so it is what it is.
// ill try to refactor things regularly when i have time, and whenever i git gud. 

int main(int argc, char* argv) {
	HANDLE proc = Utils::Processes::GetProcessHandleAllPerms(L"proc.exe");
	std::cout << "PID: " << GetProcessId(proc) << std::endl;
	Utils::Processes::stInjection n = Utils::Processes::InjectIntoProcess(proc, "C:\\Users\\thingscrazyroundhere\\mock.dll");
	std::cout << "thread: " << n.success << std::endl;
	std::cin.get();
	return 0;
}