#include "stdafx.h"
#pragma hdrstop

#include "xrDebug.h"
#include "os_clipboard.h"
#include "log.h"
#if defined(WINDOWS)
#include "Debug/dxerr.h"
#endif
#include "Threading/ScopeLock.hpp"

#pragma warning(push)
#pragma warning(disable : 4091) // 'typedef ': ignored on left of '' when no variable is declared
#if defined(WINDOWS)
#include "Debug/MiniDump.h"
#pragma warning(pop)
#include <malloc.h>
#include <direct.h>
#endif

extern bool shared_str_initialized;


static BOOL bException = FALSE;



#include <exception>

#include <new.h> // for _set_new_mode
#include <signal.h> // for signals
#include <errorrep.h> // ReportFault

#pragma comment(lib, "FaultRep.lib")

#if defined(DEBUG) || defined(COC_DEBUG)
#define USE_OWN_ERROR_MESSAGE_WINDOW
#else
#define USE_OWN_MINI_DUMP
#endif

#if defined XR_X64
#define MACHINE_TYPE IMAGE_FILE_MACHINE_AMD64
#elif defined XR_X86
#define MACHINE_TYPE IMAGE_FILE_MACHINE_I386
#else
#error CPU architecture is not supported.
#endif

namespace
{
ICN void* GetInstructionPtr()
{
#if defined(LINUX)
    pid_t traced_process;
    struct user_regs_struct regs;
    ptrace(PTRACE_ATTACH, traced_process, NULL, NULL);
    ptrace(PTRACE_GETREGS, traced_process, NULL, &regs);

    return regs.rip;
#else
#ifdef _MSC_VER
    return _ReturnAddress();
#else
#ifdef _WIN64
    _asm mov rax, [rsp] _asm retn
#else
    _asm mov eax, [esp] _asm retn
#endif
#endif
#endif
}
} // namespace

static void ShowMSGboxAboutError() //MNP
{
    MessageBox(NULL, "Fatal error. Check crash log for more info.", "X-Ray Unofficial Patch Engine", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
}

xrDebug::UnhandledExceptionFilter xrDebug::PrevFilter = nullptr;
xrDebug::OutOfMemoryCallbackFunc xrDebug::OutOfMemoryCallback = nullptr;
xrDebug::CrashHandler xrDebug::OnCrash = nullptr;
xrDebug::DialogHandler xrDebug::OnDialog = nullptr;
string_path xrDebug::BugReportFile;
bool xrDebug::ErrorAfterDialog = false;

bool xrDebug::symEngineInitialized = false;
Lock xrDebug::dbgHelpLock;

#if defined(WINDOWS)
void xrDebug::SetBugReportFile(const char* fileName) { strcpy_s(BugReportFile, fileName); }
#elif defined(LINUX)
void xrDebug::SetBugReportFile(const char* fileName) { strcpy_s(BugReportFile, 0, fileName); }
#endif

#if defined(WINDOWS)
bool xrDebug::GetNextStackFrameString(LPSTACKFRAME stackFrame, PCONTEXT threadCtx, xr_string& frameStr)
{
    BOOL result = StackWalk(MACHINE_TYPE, GetCurrentProcess(), GetCurrentThread(), stackFrame, threadCtx, nullptr,
        SymFunctionTableAccess, SymGetModuleBase, nullptr);

    if (result == FALSE || stackFrame->AddrPC.Offset == 0)
    {
        return false;
    }

    frameStr.clear();
    string512 formatBuff;

    ///
    /// Module name
    ///
    HINSTANCE hModule = (HINSTANCE)SymGetModuleBase(GetCurrentProcess(), stackFrame->AddrPC.Offset);
    if (hModule && GetModuleFileName(hModule, formatBuff, _countof(formatBuff)))
    {
        frameStr.append(formatBuff);
    }

    ///
    /// Address
    ///
    xr_sprintf(formatBuff, _countof(formatBuff), " at %p", stackFrame->AddrPC.Offset);
    frameStr.append(formatBuff);

    ///
    /// Function info
    ///
    BYTE arrSymBuffer[512];
    ZeroMemory(arrSymBuffer, sizeof(arrSymBuffer));
    PIMAGEHLP_SYMBOL functionInfo = reinterpret_cast<PIMAGEHLP_SYMBOL>(arrSymBuffer);
    functionInfo->SizeOfStruct = sizeof(*functionInfo);
    functionInfo->MaxNameLength = sizeof(arrSymBuffer) - sizeof(*functionInfo) + 1;
    DWORD_PTR dwFunctionOffset;

    result = SymGetSymFromAddr(GetCurrentProcess(), stackFrame->AddrPC.Offset, &dwFunctionOffset, functionInfo);

    if (result)
    {
        if (dwFunctionOffset)
        {
            xr_sprintf(formatBuff, _countof(formatBuff), " %s() + %Iu byte(s)", functionInfo->Name, dwFunctionOffset);
        }
        else
        {
            xr_sprintf(formatBuff, _countof(formatBuff), " %s()", functionInfo->Name);
        }
        frameStr.append(formatBuff);
    }

    ///
    /// Source info
    ///
    DWORD dwLineOffset;
    IMAGEHLP_LINE sourceInfo = {};
    sourceInfo.SizeOfStruct = sizeof(sourceInfo);

    result = SymGetLineFromAddr(GetCurrentProcess(), stackFrame->AddrPC.Offset, &dwLineOffset, &sourceInfo);

    if (result)
    {
        if (dwLineOffset)
        {
            xr_sprintf(formatBuff, _countof(formatBuff), " in %s line %u + %u byte(s)", sourceInfo.FileName,
                sourceInfo.LineNumber, dwLineOffset);
        }
        else
        {
            xr_sprintf(formatBuff, _countof(formatBuff), " in %s line %u", sourceInfo.FileName, sourceInfo.LineNumber);
        }
        frameStr.append(formatBuff);
    }

    return true;
}

bool xrDebug::InitializeSymbolEngine()
{
    if (!symEngineInitialized)
    {
        DWORD dwOptions = SymGetOptions();
        SymSetOptions(dwOptions | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES | SYMOPT_UNDNAME);

        if (SymInitialize(GetCurrentProcess(), nullptr, TRUE))
        {
            symEngineInitialized = true;
        }
    }

    return symEngineInitialized;
}

void xrDebug::DeinitializeSymbolEngine(void)
{
    if (symEngineInitialized)
    {
        SymCleanup(GetCurrentProcess());

        symEngineInitialized = false;
    }
}

xr_vector<xr_string> xrDebug::BuildStackTrace(PCONTEXT threadCtx, u16 maxFramesCount)
{
    ScopeLock Lock(&dbgHelpLock);

    SStringVec traceResult;
    STACKFRAME stackFrame = {};
    xr_string frameStr;

    if (!InitializeSymbolEngine())
    {
        Msg("[xrDebug::BuildStackTrace]InitializeSymbolEngine failed with error: %d", GetLastError());
        return traceResult;
    }

    traceResult.reserve(maxFramesCount);

#if defined XR_X64
    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrPC.Offset = threadCtx->Rip;
    stackFrame.AddrStack.Mode = AddrModeFlat;
    stackFrame.AddrStack.Offset = threadCtx->Rsp;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Offset = threadCtx->Rbp;
#elif defined XR_X86
    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrPC.Offset = threadCtx->Eip;
    stackFrame.AddrStack.Mode = AddrModeFlat;
    stackFrame.AddrStack.Offset = threadCtx->Esp;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Offset = threadCtx->Ebp;
#else
#error CPU architecture is not supported.
#endif

    while (GetNextStackFrameString(&stackFrame, threadCtx, frameStr) && traceResult.size() <= maxFramesCount)
    {
        traceResult.push_back(frameStr);
    }

    DeinitializeSymbolEngine();

    return traceResult;
}

SStringVec xrDebug::BuildStackTrace(u16 maxFramesCount)
{
    CONTEXT currentThreadCtx = {};

    RtlCaptureContext(&currentThreadCtx); /// GetThreadContext can't be used on the current thread
    currentThreadCtx.ContextFlags = CONTEXT_FULL;

    return BuildStackTrace(&currentThreadCtx, maxFramesCount);
}

void xrDebug::LogStackTrace(const char* header)
{
    SStringVec stackTrace = BuildStackTrace();
    Msg("%s", header);
    for (const auto& frame : stackTrace)
    {
        Msg("%s", frame.c_str());
    }
}
#endif // defined(WINDOWS)

void xrDebug::GatherInfo(char* assertionInfo, const ErrorLocation& loc, const char* expr, const char* desc,
    const char* arg1, const char* arg2)
{
    char* buffer = assertionInfo;
    if (!expr)
        expr = "<no expression>";
    bool extendedDesc = desc && strchr(desc, '\n');
    pcstr prefix = "[error] ";
    buffer += sprintf(buffer, "\nFATAL ERROR\n\n");
    buffer += sprintf(buffer, "%sExpression    : %s\n", prefix, expr);
    buffer += sprintf(buffer, "%sFunction      : %s\n", prefix, loc.Function);
    buffer += sprintf(buffer, "%sFile          : %s\n", prefix, loc.File);
    buffer += sprintf(buffer, "%sLine          : %d\n", prefix, loc.Line);
    if (extendedDesc)
    {
        buffer += sprintf(buffer, "\n%s\n", desc);
        if (arg1)
        {
            buffer += sprintf(buffer, "%s\n", arg1);
            if (arg2)
                buffer += sprintf(buffer, "%s\n", arg2);
        }
    }
    else
    {
        buffer += sprintf(buffer, "%sDescription   : %s\n", prefix, desc);
        if (arg1)
        {
            if (arg2)
            {
                buffer += sprintf(buffer, "%sArgument 0    : %s\n", prefix, arg1);
                buffer += sprintf(buffer, "%sArgument 1    : %s\n", prefix, arg2);
            }
            else
                buffer += sprintf(buffer, "%sArguments     : %s\n", prefix, arg1);
        }
    }
    buffer += sprintf(buffer, "\n");
    if (shared_str_initialized)
    {
        Log(assertionInfo);
        FlushLog();
    }
    buffer = assertionInfo;

    if (shared_str_initialized)
        Log("stack trace:\n");
#ifdef USE_OWN_ERROR_MESSAGE_WINDOW
    buffer += sprintf(buffer, "stack trace:\n\n");
#endif // USE_OWN_ERROR_MESSAGE_WINDOW
    xr_vector<xr_string> stackTrace = BuildStackTrace();
    for (size_t i = 2; i < stackTrace.size(); i++)
    {
        if (shared_str_initialized)
            Log(stackTrace[i].c_str());
#ifdef USE_OWN_ERROR_MESSAGE_WINDOW
        buffer += sprintf(buffer, "%s\n", stackTrace[i].c_str());
#endif // USE_OWN_ERROR_MESSAGE_WINDOW
    }
    if (shared_str_initialized)
        FlushLog();
    os_clipboard::copy_to_clipboard(assertionInfo);
}

void xrDebug::Fatal(const ErrorLocation& loc, const char* format, ...)
{
    string1024 desc;
    va_list args;
    va_start(args, format);
    vsnprintf(desc, sizeof(desc), format, args);
    va_end(args);
    bool ignoreAlways = true;
    Fail(ignoreAlways, loc, nullptr, "fatal error", desc);
}

void xrDebug::Fail(
    bool& ignoreAlways, const ErrorLocation& loc, const char* expr, long hresult, const char* arg1, const char* arg2)
{
    Fail(ignoreAlways, loc, expr, xrDebug::ErrorToString(hresult), arg1, arg2);
}

void xrDebug::Fail(bool& ignoreAlways, const ErrorLocation& loc, const char* expr, const char* desc, const char* arg1,
    const char* arg2)
{
#ifdef PROFILE_CRITICAL_SECTIONS
    static Lock lock(MUTEX_PROFILE_ID(xrDebug::Backend));
#else
    static Lock lock;
#endif
    lock.Enter();
    ErrorAfterDialog = true;
    // clang-format off
    constexpr char managedFail[] =""
"___  ___                                 _______    _ _ \n"
"|  \\/  |                                | |  ___|  (_) |\n"
"| .  . | __ _ _ __   __ _  __ _  ___  __| | |_ __ _ _| |\n"
"| |\\/| |/ _` | '_ \\ / _` |/ _` |/ _ \\/ _` |  _/ _` | | |\n"
"| |  | | (_| | | | | (_| | (_| |  __/ (_| | || (_| | | |\n"
"\\_|  |_/\\__,_|_| |_|\\__,_|\\__, |\\___|\\__,_\\_| \\__,_|_|_|\n"
"                           __/ |                        \n"
"                          |___/                         ";
    // clang-format on
    Log(managedFail);
    string4096 assertionInfo;
    GatherInfo(assertionInfo, loc, expr, desc, arg1, arg2);

    if (OnDialog)
        OnDialog(true);
    OnCrash();
    FlushLog();

    while (ShowCursor(true) < 0);
    ShowWindow(GetActiveWindow(), SW_FORCEMINIMIZE);

    ShowMSGboxAboutError();
    if (OnDialog)
        OnDialog(false);

    lock.Leave();
    TerminateProcess(GetCurrentProcess(), 1);
}

void xrDebug::Fail(bool& ignoreAlways, const ErrorLocation& loc, const char* expr, const std::string& desc,
    const char* arg1, const char* arg2)
{
    Fail(ignoreAlways, loc, expr, desc.c_str(), arg1, arg2);
}

// AVO
void xrDebug::SoftFail(const ErrorLocation& loc, const char* expr, const char* desc, const char* arg1, const char* arg2)
{
    if (desc == nullptr)
    {
        // Msg("! VERIFY_FAILED: %s[%d] {%s}  %s", loc.File, loc.Line, loc.Function, expr);
        Msg("! VERIFY_FAILED: %s[%d] %s", loc.File, loc.Line, expr);
        return;
    }

    std::string buffer = desc;
    if (arg1 != nullptr)
    {
        buffer = buffer + std::string(" ") + arg1;
        if (arg2 != nullptr)
            buffer = buffer + std::string(" ") + arg2;
    }

    // Msg("! VERIFY_FAILED: %s[%d] {%s}  %s %s", loc.File, loc.Line, loc.Function, expr, buffer.c_str());
    Msg("! VERIFY_FAILED: %s[%d] %s %s", loc.File, loc.Line, expr, buffer.c_str());
}

void xrDebug::SoftFail(
    const ErrorLocation& loc, const char* expr, const std::string& desc, const char* arg1, const char* arg2)
{
    std::string buffer = desc;
    if (arg1 != nullptr)
    {
        buffer = buffer + std::string(" ") + arg1;
        if (arg2 != nullptr)
            buffer = buffer + std::string(" ") + arg2;
    }

    Msg("! VERIFY_FAILED: %s[%d] {%s}  %s %s", loc.File, loc.Line, loc.Function, expr, buffer.c_str());
}
//-AVO

void xrDebug::DoExit(const std::string& message)
{
    FlushLog();
#if defined(WINDOWS)
    MessageBox(NULL, message.c_str(), "Error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
    TerminateProcess(GetCurrentProcess(), 1);
#endif
}

LPCSTR xrDebug::ErrorToString(long code)
{
    const char* result = nullptr;
    static string1024 descStorage;
#if defined(WINDOWS)
    DXGetErrorDescription(code, descStorage, sizeof(descStorage));
    if (!result)
    {
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, 0, code, 0, descStorage, sizeof(descStorage) - 1, 0);
        result = descStorage;
    }
#endif
    return result;
}

int out_of_memory_handler(size_t size)
{
    xrDebug::OutOfMemoryCallbackFunc cb = xrDebug::GetOutOfMemoryCallback();
    if (cb)
        cb();
    else
    {
        Memory.mem_compact();
        size_t processHeap = Memory.mem_usage();
        size_t ecoStrings = g_pStringContainer->stat_economy();
        size_t ecoSmem = g_pSharedMemoryContainer->stat_economy();
        Msg("* [x-ray]: process heap[%zu K]", processHeap / 1024);
        Msg("* [x-ray]: economy: strings[%zu K], smem[%zu K]", ecoStrings / 1024, ecoSmem);
    }
    xrDebug::Fatal(DEBUG_INFO, "Out of memory. Memory request: %zu K", size / 1024);
    return 1;
}

extern LPCSTR log_name();

void xrDebug::FormatLastError(char* buffer, const size_t& bufferSize)
{
#if defined(WINDOWS)
    int lastErr = GetLastError();
    if (lastErr == ERROR_SUCCESS)
    {
        *buffer = 0;
        return;
    }
    void* msg = nullptr;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, nullptr, lastErr,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&msg, 0, nullptr);
    // XXX nitrocaster: check buffer overflow
    sprintf(buffer, "[error][%8d]: %s", lastErr, (char*)msg);
    LocalFree(msg);
#endif
}

LONG WINAPI xrDebug::UnhandledFilter(EXCEPTION_POINTERS* exPtrs)
{
	static Lock lock;
	lock.Enter();
    string256 errMsg;
    FormatLastError(errMsg, sizeof(errMsg));
    if (!ErrorAfterDialog && !strstr(GetCommandLine(), "-no_call_stack_assert"))
    {
        CONTEXT save = *exPtrs->ContextRecord;
        xr_vector<xr_string> stackTrace = BuildStackTrace(exPtrs->ContextRecord, 1024);
        *exPtrs->ContextRecord = save;
        // clang-format off
        constexpr char unhandledText[] = ""
        " _   _       _                     _ _          _   _____                   _   _             \n"
        "| | | |     | |                   | | |        | | |  ___|                 | | (_)            \n"
        "| | | |_ __ | |__   __ _ _ __   __| | | ___  __| | | |____  _____ ___ _ __ | |_ _  ___  _ __  \n"
        "| | | | '_ \\| '_ \\ / _` | '_ \\ / _` | |/ _ \\/ _` | |  __\\ \\/ / __/ _ \\ '_ \\| __| |/ _ \\| '_ \\ \n"
        "| |_| | | | | | | | (_| | | | | (_| | |  __/ (_| | | |___>  < (_|  __/ |_) | |_| | (_) | | | |\n"
        " \\___/|_| |_|_| |_|\\__,_|_| |_|\\__,_|_|\\___|\\__,_| \\____/_/\\_\\___\\___| .__/ \\__|_|\\___/|_| |_|\n"
        "                                                                     | |                      \n"
        "                                                                     |_|                      \n"
        "stack trace:\n\n";
        // clang-format on
        if (shared_str_initialized)
            Msg(unhandledText);
        if (!IsDebuggerPresent())
            os_clipboard::copy_to_clipboard(unhandledText);
        string4096 buffer;
        for (size_t i = 0; i < stackTrace.size(); i++)
        {
            if (shared_str_initialized)
                Log(stackTrace[i].c_str());
            sprintf(buffer, "%s\r\n", stackTrace[i].c_str());
#ifdef DEBUG
            if (!IsDebuggerPresent())
                os_clipboard::update_clipboard(buffer);
#endif
        }
        if (*errMsg)
        {
            if (shared_str_initialized)
                Msg("\n%s", errMsg);
            strcat(errMsg, "\r\n");
#ifdef DEBUG
            if (!IsDebuggerPresent())
                os_clipboard::update_clipboard(buffer);
#endif
        }
    }
    OnCrash();
    FlushLog();
    ShowWindow(GetActiveWindow(), SW_FORCEMINIMIZE);
    ShowMSGboxAboutError();
	lock.Leave();
    TerminateProcess(GetCurrentProcess(), 1);
    return EXCEPTION_EXECUTE_HANDLER;
}

static void handler_base(const char* reason)
{
    bool ignoreAlways = false;
    xrDebug::Fail(ignoreAlways, DEBUG_INFO, nullptr, reason, nullptr, nullptr);
}

static void invalid_parameter_handler(
    const wchar_t* expression, const wchar_t* function, const wchar_t* file, unsigned int line, uintptr_t reserved)
{
#if defined(WINDOWS)
    bool ignoreAlways = false;
    string4096 mbExpression;
    string4096 mbFunction;
    string4096 mbFile;
    size_t convertedChars = 0;
    if (expression)
        wcstombs_s(&convertedChars, mbExpression, sizeof(mbExpression), expression, (wcslen(expression) + 1) * 2);
    else
        xr_strcpy(mbExpression, "");
    if (function)
        wcstombs_s(&convertedChars, mbFunction, sizeof(mbFunction), function, (wcslen(function) + 1) * 2);
    else
        xr_strcpy(mbFunction, __FUNCTION__);
    if (file)
        wcstombs_s(&convertedChars, mbFile, sizeof(mbFile), file, (wcslen(file) + 1) * 2);
    else
    {
        line = __LINE__;
        xr_strcpy(mbFile, __FILE__);
    }
    xrDebug::Fail(ignoreAlways, {mbFile, int(line), mbFunction}, mbExpression, "invalid parameter");
#endif
}

static void pure_call_handler() { handler_base("pure virtual function call"); }
#ifdef XRAY_USE_EXCEPTIONS
static void unexpected_handler() { handler_base("unexpected program termination"); }
#endif

static void abort_handler(int signal) { handler_base("application is aborting"); }
static void floating_point_handler(int signal) { handler_base("floating point error"); }
static void illegal_instruction_handler(int signal) { handler_base("illegal instruction"); }
static void termination_handler(int signal) { handler_base("termination with exit code 3"); }

void xrDebug::OnThreadSpawn()
{
#if defined(WINDOWS)
#ifdef USE_BUG_TRAP
    BT_SetTerminate();
#else
    // std::set_terminate(_terminate);
#endif
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    signal(SIGABRT, abort_handler);
    signal(SIGABRT_COMPAT, abort_handler);
    signal(SIGFPE, floating_point_handler);
    signal(SIGILL, illegal_instruction_handler);
    signal(SIGINT, 0);
    signal(SIGTERM, termination_handler);
    _set_invalid_parameter_handler(&invalid_parameter_handler);
    _set_new_mode(1);
    _set_new_handler(&out_of_memory_handler);
    _set_purecall_handler(&pure_call_handler);
#if 0 // should be if we use exceptions
    std::set_unexpected(_terminate);
#endif
#endif
}

void xrDebug::Initialize(const bool& dedicated)
{
    *BugReportFile = 0;
    OnThreadSpawn();
#ifdef USE_BUG_TRAP
    SetupExceptionHandler(dedicated);
#endif
    // exception handler to all "unhandled" exceptions
#if defined(WINDOWS)
    PrevFilter = ::SetUnhandledExceptionFilter(UnhandledFilter);
#endif
}
