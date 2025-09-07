#pragma once


#define CONCAT_IMPL(...) __VA_ARGS__
#define CONCAT_ARGS(...) CONCAT_IMPL(__VA_ARGS__)

size_t FindPattern(const char* module, const char* funcname, const char* pattern, const char* mask);

#define X86_THISCALL_HOOK_HELPER_DEFINE_FUNCTION(classname, name, returnvalue, args) \
inline static returnvalue (classname::* o_##name)(args); \
returnvalue h_##name(args)

#define X86_NONTHISCALL_HOOK_HELPER_DEFINE_FUNCTION(name, callconv, returnvalue, args) \
returnvalue (callconv* o_##name)(args);\
returnvalue callconv h_##name(args)

template<typename T>
void* get_class_func_addr(T* func)
{
  union {
    T* pfunc;
    void* addr;
  };
  pfunc = func;
  return addr;
}

template<typename classT, typename memberT>
void* get_class_func_addr(memberT classT::* func)
{
  union {
    memberT classT::* pfunc;
    void* addr;
  };
  pfunc = func;
  return addr;
}

#define MH_STATUS_CHECK(debugname, status)\
if(status != MH_OK) {\
std::cout << debugname ": " << MH_StatusToString(status);\
}
#define HOOK_HELPERS_CREATE_HOOK(name, addr_, hook_addr, original_addr) \
{\
auto addr = (void*)(addr_); \
MH_STATUS status = MH_CreateHook((LPVOID)(addr), (hook_addr), (LPVOID*)(original_addr));\
MH_STATUS_CHECK(name " CreateHook", status);\
status = MH_EnableHook((LPVOID)(addr));\
MH_STATUS_CHECK(name " EnableHook", status);\
}

#define X86_THISCALL_HOOK_HELPER_HOOK_CLASS_FUNCTION_ADDRESS(classname, name, address) \
HOOK_HELPERS_CREATE_HOOK(#classname "::" #name, address, get_class_func_addr(&classname::h_##name), get_class_func_addr(&classname::o_##name));

#define X86_THISCALL_HOOK_HELPER_HOOK_CLASS_FUNCTION(classname, name, pattern, mask) \
X86_THISCALL_HOOK_HELPER_HOOK_CLASS_FUNCTION_ADDRESS(classname, name, FindPattern(gameexecutable, #classname "::" #name, pattern, mask));
#define X86_NONTHISCALL_HOOK_HELPER_HOOK_FUNCTION(name, pattern, mask) \
HOOK_HELPERS_CREATE_HOOK(#name, FindPattern(gameexecutable, #name, pattern, mask), h_##name, &o_##name)
