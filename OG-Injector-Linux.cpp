#include "OG-Injector-Linux.hpp"

using namespace std;

// Process name
constexpr auto PROCESS_NAME = "csgo_linux64";
// Shared library name
constexpr auto LIBRARY_NAME = "library.so";

//#define OSIRIS
//#define GOESP
//#define BETA

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
        if (!ranges::all_of(path->begin(), path->end(), ::isdigit))
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

    cout << "\033[1;31m   ____       _      _         __   __________  ___________ ____ " << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    cout << "\033[1;32m  / __ \\_____(_)____(_)____   / /  / ____/ __ \\/ ____/ ___// __ \\" << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    cout << "\033[1;33m / / / / ___/ / ___/ / ___/  / /  / / __/ / / / __/  \\__ \\/ /_/ /" << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    cout << "\033[1;34m/ /_/ (__  ) / /  / (__  )  / /  / /_/ / /_/ / /___ ___/ / ____/ " << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    cout << "\033[1;35m\\____/____/_/_/  /_/____/  / /   \\____/\\____/_____//____/_/      " << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    cout << "\033[1;36m    ____  __            __///                                    " << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    cout << "\033[1;31m   / __ \\/ /___ ___  __/ __ \\____ ___  __                        " << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    cout << "\033[1;32m  / /_/ / / __ `/ / / / / / / __ `/ / / /                        " << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    cout << "\033[1;33m / ____/ / /_/ / /_/ / /_/ / /_/ / /_/ /                         " << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    cout << "\033[1;34m/_/   /_/\\__,_/\\__, /_____/\\__,_/\\__, /                          " << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    cout << "\033[1;35m              /____/            /____/                           " << endl << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    cout << "\033[1;37mBuild: " __DATE__ ", " __TIME__ "\033[0m\n" << endl << endl;
    this_thread::sleep_for(chrono::milliseconds(50));

    #pragma endregion
    
    auto ptrace_scope = make_unique<ifstream>("/proc/sys/kernel/yama/ptrace_scope")->get();
    auto euid = geteuid();
    if (ptrace_scope == 49 && euid) {
        cerr << "If you want run injector without root privileges you need to change '/proc/sys/kernel/yama/ptrace_scope' variable to 0" << endl;
        cerr << "Use this command to do this: \033[1mecho 1 | sudo tee /proc/sys/kernel/yama/ptrace_scope\033[0m" << endl;
        cerr << "After injectoin you can return the value back" << endl;
        cerr << "Use this command to do this: \033[1mecho 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope\033[0m" << endl << endl;
        cerr << "If you dont want to change any kernel variable, you can just run this injector as root" << endl;
        if (WIFEXITED(system("which sudo > /dev/null 2>&1")))
            cout << "Use this command to do this: sudo " << argv[0] << endl << endl;
        cout << "Press any key to continue..." << endl;
        cin.get();
        return EXIT_FAILURE;
    }
    else if (ptrace_scope == 48 && euid) {
        cout << "Detected disabled kernel variable '/proc/sys/kernel/yama/ptrace_scope'" << endl;
        cout << "If you changed it from '1' to '0' only in order to launch the injector, then change it back to '0' after the injection" << endl;
        cout << "Use this command to do this: \033[1mecho 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope\033[0m" << endl;
    }
    else if (ptrace_scope == -1 && euid) {
        cerr << "\033[31mPlease restart injector as root\033[0m" << endl;
        if (WIFEXITED(system("which sudo > /dev/null 2>&1")))
            cout << "Use this command to do this: \033[1msudo " << argv[0] << "\033[0m" << endl << endl;
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
        cout << "\033[1mLibrary: " << soname << " found" << "\033[0m" << endl;
    else {
        cerr << "\033[31mCan't find: " << soname << "\033[0m" << endl;
        cout << "Press any key to continue..." << endl;
        cin.get();
        return EXIT_FAILURE;
    }

    pid_t pid = findProcess(PROCESS_NAME);
    if (pid != INVALID_PID) 
        cout << "\033[1mFound process '" << PROCESS_NAME << "' with PID: " << pid << "\033[0m" << endl;
    else {
        cerr << "\033[31mCan't find: " << PROCESS_NAME << "\033[0m" << endl;
        cout << "Press any key to continue..." << endl;
        cin.get();
        return EXIT_FAILURE;
    }
    
    cout << "\033[1mProcess: " << PROCESS_NAME << " found with PID: " << pid << endl <<
        "Injecting " << soname << " into " << PROCESS_NAME << "\033[0m" << endl;

    injector_t *injector;

    if (injector_attach(&injector, pid) != 0) {
        cerr << "\033[31mCan't attach injector to '" << PROCESS_NAME << "'\033[0m" << endl;
        cerr << injector_error() << endl;
        cout << "Press any key to continue..." << endl;
        cin.get();
        return EXIT_FAILURE;
    }
    if (injector_inject(injector, soname.c_str(), NULL) == 0)
        cout << "\033[1;32mSuccessfully injected '" << soname.c_str() << "' into '" << PROCESS_NAME << "'\033[0m" << endl;
    else {
        cerr << "\033[31mCan't inject " << soname.c_str() << "' into '" << PROCESS_NAME << "'\033[0m" << endl;
        cerr << injector_error() << endl;
        cout << "Press any key to continue..." << endl;
        cin.get();
        return EXIT_FAILURE;
    }
    injector_detach(injector);

	cout << "\033[1mYou have 5 seconds to read this information, GOODBYE\033[0m" << endl;
	this_thread::sleep_for(chrono::seconds(5));

    return EXIT_SUCCESS;
}
