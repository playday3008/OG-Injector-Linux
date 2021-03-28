#include "OG-Injector-Linux.hpp"

using namespace std;

// Process name
constexpr auto PROCESS_NAME = "csgo_linux64";
// Shared library name
constexpr auto LIBRARY_NAME = "library.so";

//#define OSIRIS
//#define GOESP
//#define BETA

// Terminal colored output
constexpr auto RESET = "\033[0m";
constexpr auto BLACK = "\033[30m";      /* Black */
constexpr auto RED = "\033[31m";        /* Red */
constexpr auto GREEN = "\033[32m";      /* Green */
constexpr auto YELLOW = "\033[33m";     /* Yellow */
constexpr auto BLUE = "\033[34m";       /* Blue */
constexpr auto MAGENTA = "\033[35m";    /* Magenta */
constexpr auto CYAN = "\033[36m";       /* Cyan */
constexpr auto WHITE = "\033[37m";      /* White */
constexpr auto BOLD = "\033[1m";        /* Bold */

#if (defined(OSIRIS) || defined(GOESP))
// Check CPU supported features
inline void checkinst(array<bool, 3>& inst)
{
    // An array of four integers that contains the information returned in EAX, EBX, ECX, and EDX about supported features of the CPU.
    array<int, 4> CPUInfo{};
    // Get Features
    __cpuid_count(0, 0, CPUInfo.at(0), CPUInfo.at(1), CPUInfo.at(2), CPUInfo.at(3));
    auto nIds = CPUInfo.at(0);

    //  Detect Features
    if (nIds >= 0x00000001) {
        // Detect SSE2 & AVX
        __cpuid_count(0x00000001, 0, CPUInfo.at(0), CPUInfo.at(1), CPUInfo.at(2), CPUInfo.at(3));
        // SSE2
        inst.at(0) = (CPUInfo.at(3) & (1 << 26)) != 0;
        // AVX
        inst.at(1) = (CPUInfo.at(2) & (1 << 28)) != 0;
    }
    if (nIds >= 0x00000007) {
        // Detect AVX2
        __cpuid_count(0x00000007, 0, CPUInfo.at(0), CPUInfo.at(1), CPUInfo.at(2), CPUInfo.at(3));
        // AVX2
        inst.at(2) = (CPUInfo.at(1) & (1 << 5)) != 0;
    }

    return;
};
#endif

// Get process ID by process name
constexpr auto INVALID_PID = -1;
inline static auto findProcess(const string name)
{
    // Get '/proc' folder
    auto dir = make_unique<fs::path>("/proc");
    // Declarate 'pid' as invalid if read was failed
    pid_t pid = INVALID_PID;

    // Scan '/proc' folder
    for (auto& p : fs::directory_iterator(*dir.get())) {
        // Check if folder name contains only numbers
        auto path = make_unique<string>(p.path().filename().string());
        if (!all_of(path->begin(), path->end(), ::isdigit))
            continue;

        // Path to process
        auto exepath = make_unique<vector<char>>(PATH_MAX);
        // Check if file exists
        if(readlink((p / fs::path("exe")).c_str(), exepath->data(), exepath->size()) != -1) {
            // Get process real path then get name from this path and check if it same as 'name'
            if (fs::path(exepath->data()).filename().string() == name) {
                istringstream(p.path().filename().string()) >> pid;
                break;
            }
        }
    }
    return pid;
}

//   ____    ___                      ____                                                      
//  /\  _`\ /\_ \                    /\  _`\                                                    
//  \ \ \L\ \//\ \      __     __  __\ \ \/\ \     __     __  __                                
//   \ \ ,__/ \ \ \   /'__`\  /\ \/\ \\ \ \ \ \  /'__`\  /\ \/\ \                               
//    \ \ \/   \_\ \_/\ \L\.\_\ \ \_\ \\ \ \_\ \/\ \L\.\_\ \ \_\ \                              
//     \ \_\   /\____\ \__/.\_\\/`____ \\ \____/\ \__/.\_\\/`____ \                             
//      \/_/   \/____/\/__/\/_/ `/___/> \\/___/  \/__/\/_/ `/___/> \                            
//                                 /\___/                     /\___/                            
//

int main(int argc, char** argv)
{
    #pragma region Logo

    cout << BOLD << RED << R"(   ____  ______   ____        _           __)" << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    cout << BOLD << GREEN << R"(  / __ \/ ____/  /  _/___    (_)__  _____/ /_____  _____)" << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    cout << BOLD << YELLOW << R"( / / / / / __    / // __ \  / / _ \/ ___/ __/ __ \/ ___/)" << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    cout << BOLD << BLUE << R"(/ /_/ / /_/ /  _/ // / / / / /  __/ /__/ /_/ /_/ / /)" << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    cout << BOLD << MAGENTA << R"(\____/\____/  /___/_/ /_/_/ /\___/\___/\__/\____/_/)" << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    cout << BOLD << CYAN << R"(    ____  __           /___/)" << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    cout << BOLD << RED << R"(   / __ \/ /___ ___  __/ __ \____ ___  __)" << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    cout << BOLD << GREEN << R"(  / /_/ / / __ `/ / / / / / / __ `/ / / /)" << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    cout << BOLD << YELLOW << R"( / ____/ / /_/ / /_/ / /_/ / /_/ / /_/ /)" << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    cout << BOLD << BLUE << R"(/_/   /_/\__,_/\__, /_____/\__,_/\__, /)" << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    cout << BOLD << MAGENTA << R"(              /____/            /____/)" << endl << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    cout << BOLD << WHITE << "Build: " __DATE__ ", " __TIME__ << RESET << endl << endl;
    this_thread::sleep_for(chrono::milliseconds(50));

    #pragma endregion
    
    auto ptrace_scope = make_unique<ifstream>("/proc/sys/kernel/yama/ptrace_scope")->get();
    auto euid = geteuid();
    if (ptrace_scope == 49 && euid) {
        cerr << "If you want run injector without root privileges you need to change '/proc/sys/kernel/yama/ptrace_scope' variable to 0" << endl;
        cerr << "Use this command to do this: " << BOLD << RED << "echo 1 | sudo tee /proc/sys/kernel/yama/ptrace_scope" << RESET << endl;
        cerr << "After injectoin you can return the value back" << endl;
        cerr << "Use this command to do this: " << BOLD << RED << "echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope" << RESET << endl << endl;
        cerr << "If you dont want to change any kernel variable, you can just run this injector as root" << endl;
        if (WIFEXITED(system("which sudo > /dev/null 2>&1")))
            cout << "Use this command to do this: " << BOLD << RED << "sudo " << argv[0] << RESET << endl << endl;
        cout << "Press any key to continue..." << endl;
        cin.get();
        return EXIT_FAILURE;
    }
    else if (ptrace_scope == 48 && euid) {
        cout << "Detected disabled kernel variable '/proc/sys/kernel/yama/ptrace_scope'" << endl;
        cout << "If you changed it from '1' to '0' only in order to launch the injector, then change it back to '0' after the injection" << endl;
        cout << "Use this command to do this: " << YELLOW << "echo 1 | sudo tee /proc/sys/kernel/yama/ptrace_scope" << RESET << endl;
    }
    else if (ptrace_scope == -1 && euid) {
        cerr << BOLD << RED << "Please restart injector as root" << RESET << endl;
        if (WIFEXITED(system("which sudo > /dev/null 2>&1")))
            cout << "Use this command to do this: " << BOLD << RED << "sudo " << argv[0] << RESET << endl << endl;
        cout << "Press any key to continue..." << endl;
        cin.get();
        return EXIT_FAILURE;
    }

    string soname = LIBRARY_NAME;

    #pragma region Osiris and GOESP part

    #ifdef OSIRIS
    soname = "libOsiris";
    #elif defined(GOESP)
    soname = "libGOESP";
    #endif

    #if (defined(OSIRIS) || defined(GOESP)) && defined(BETA)
    soname += "_BETA";
    #endif

    #if (defined(OSIRIS) || defined(GOESP))
    // Get processor instructions
    array<bool, 3> inst{};
    checkinst(inst);

    if (inst.at(2))
        soname += "_AVX2.so";
    else if (inst.at(1))
        soname += "_AVX.so";
    else if (inst.at(0))
        soname += "_SSE2.so";
    #endif

    #pragma endregion

    if (fs::exists(fs::path(soname.c_str())))
        cout << GREEN << "Library: " << BOLD << soname << RESET << GREEN << " found" << RESET << endl;
    else {
        cerr << RED << "Can't find: " << BOLD << soname << RESET << endl;
        cout << BOLD << "Press any key to continue..." << endl;
        cin.get();
        return EXIT_FAILURE;
    }

    pid_t pid = findProcess(PROCESS_NAME);
    if (pid != INVALID_PID) 
        cout << GREEN << "Found process '" << BOLD << PROCESS_NAME << RESET << GREEN << "' with PID: " << BOLD << pid << RESET << endl;
    else {
        cerr << RED << "Can't find: " << BOLD << PROCESS_NAME << RESET << endl;
        cout << BOLD << "Press any key to continue..." << endl;
        cin.get();
        return EXIT_FAILURE;
    }
    
    cout << YELLOW << "Injecting " << BOLD << soname << RESET << YELLOW << " into " << BOLD << PROCESS_NAME << RESET << endl;

    injector_t *injector;

    if (injector_attach(&injector, pid) != 0) {
        cerr << RED << "Can't attach injector to '" << BOLD << PROCESS_NAME << RESET << RED << "'" << RESET << endl;
        cerr << injector_error() << endl;
        cout << BOLD << "Press any key to continue..." << endl;
        cin.get();
        return EXIT_FAILURE;
    }
    if (injector_inject(injector, soname.c_str(), NULL) == 0)
        cout << BOLD << GREEN << "Successfully injected '" << BOLD << CYAN << soname.c_str() << RESET << YELLOW << "' into '" << BOLD << RED << PROCESS_NAME << RESET << YELLOW << "'" << RESET << endl;
    else {
        cerr << RED << "Can't inject " << BOLD << soname.c_str() << RESET << RED << "' into '" << BOLD << PROCESS_NAME << RESET << RED << "'" << RESET << endl;
        cerr << injector_error() << endl;
        cout << BOLD << "Press any key to continue..." << endl;
        cin.get();
        return EXIT_FAILURE;
    }
    injector_detach(injector);

	cout << BOLD << "You have 5 seconds to read this information, GOODBYE" << RESET << endl;
	this_thread::sleep_for(chrono::seconds(5));

    return EXIT_SUCCESS;
}
