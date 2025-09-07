#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Psapi.h>

#include <MinHook.h>


#include "ModOverridesState.h"
#include "diesel.h"
#include "hash.h"

#include "hookhelpers.h"

#include <algorithm>
#include <iostream>
#include <set>

const char* gameexecutable = "payday_win32_release.exe";
#define GET_CLASS_FUNC(dest, pattern, mask) *((size_t*)get_class_func_addr(&dest)) = FindPattern(gameexecutable, #dest, pattern, mask);
#define GET_FUNCTION(dest, pattern, mask) *((size_t*)&dest) = FindPattern(gameexecutable, #dest, pattern, mask);
void* (__cdecl* diesel_malloc)(unsigned int size);

namespace dsl {
  struct idstring {
    unsigned long long _id;

    idstring() {}
    idstring(unsigned long long id) : _id(id) {}

    bool operator==(const dsl::idstring& other) const
    {
      return this->_id == other._id;
    }
    bool operator!=(const dsl::idstring& other) const
    {
      return !(*this == other);
    }
    bool operator<(const dsl::idstring& other) const
    {
      return this->_id < other._id;
    }
  };
  struct ResourceID {
    idstring type;
    idstring name;

    ResourceID(idstring type, idstring name) : type(type), name(name) {}
  };
}

struct DBExtKey {

  dsl::idstring _type;
  dsl::idstring _name;
  unsigned int _properties;
};


struct DB;
struct Archive;

typedef bool(__stdcall* TwoLayerTransportHook)(Archive* result, unsigned int key);
typedef void(__stdcall* DBLoadHook)(DB* db);
ModOverridesState globalModOverridesState;
std::vector<TwoLayerTransportHook> extraTwoLayerTransportHooks;
std::vector<DBLoadHook> extraDBLoadHooks;

__declspec(dllexport) void __stdcall AddTwoLayerTransportHook(TwoLayerTransportHook hook)
{
  extraTwoLayerTransportHooks.push_back(hook);
}
__declspec(dllexport) void __stdcall RemoveTwoLayerTransportHook(TwoLayerTransportHook hook)
{
  auto find = std::find(extraTwoLayerTransportHooks.begin(), extraTwoLayerTransportHooks.end(), hook);
  if(find != extraTwoLayerTransportHooks.end())
    extraTwoLayerTransportHooks.erase(find);
}
__declspec(dllexport) TwoLayerTransportHook* __stdcall GetTwoLayerTransportHooks()
{
  return extraTwoLayerTransportHooks.data();
}
__declspec(dllexport) size_t __stdcall GetTwoLayerTransportHooksSize()
{
  return extraTwoLayerTransportHooks.size();
}

__declspec(dllexport) void __stdcall AddDBLoadHook(DBLoadHook hook)
{
  extraDBLoadHooks.push_back(hook);
}
__declspec(dllexport) void __stdcall RemoveDBLoadHook(DBLoadHook hook)
{
  auto find = std::find(extraDBLoadHooks.begin(), extraDBLoadHooks.end(), hook);
  if(find != extraDBLoadHooks.end())
    extraDBLoadHooks.erase(find);
}
__declspec(dllexport) DBLoadHook* __stdcall GetDBLoadHooks()
{
  return extraDBLoadHooks.data();
}
__declspec(dllexport) size_t __stdcall GetDBLoadHooksSize()
{
  return extraDBLoadHooks.size();
}

__declspec(dllexport) bool __stdcall DoesModOverrideDBKey(unsigned int dbKey)
{
  return globalModOverridesState.IsOverriden(dbKey);
}

__declspec(dllexport) void __stdcall AddOverride(unsigned int dbKey, const char* replacementFile)
{
  if (!replacementFile || !std::filesystem::exists(replacementFile) || std::filesystem::is_directory(replacementFile))
    return;
  globalModOverridesState.AddOverride(dbKey, replacementFile);
}

struct DB {
  struct Data {
    SortMap<dsl::idstring, unsigned int> _properties;
    SortMap<DBExtKey, unsigned int> _lookup;
    unsigned int _next_key;
  };

  char PAD[0x4C];

  Data* _data;


  __forceinline int lower_bound(dsl::idstring type, dsl::idstring name) const {
    DBExtKey k;
    k._name = name;
    k._type = type;
    k._properties = 0;

    return this->_data->_lookup.lower_bound_index(&k);
  }
  __forceinline int upper_bound(dsl::idstring type, dsl::idstring name) const {
    DBExtKey k;
    k._name = name;
    k._type = type;
    k._properties = -1;

    return this->_data->_lookup.upper_bound_index(&k);
  }

  bool contains(dsl::idstring type, dsl::idstring name) const {
    return lower_bound(type, name) != upper_bound(type, name);
  }

  Pair<DBExtKey, unsigned int>& add_entry(dsl::idstring type, dsl::idstring name) {
    return _data->_lookup._data.insert(lower_bound(type, name), Pair<DBExtKey, unsigned int>{
      .first = DBExtKey{ ._type = type, ._name = name, ._properties = 0 },
        .second = ++_data->_next_key
    });
  }

  X86_THISCALL_HOOK_HELPER_DEFINE_FUNCTION(DB, load, int, CONCAT_ARGS()) {
    auto ret = (this->*o_load)();

    for (auto& hook : extraDBLoadHooks) {
      if(hook)
        hook(this);
    }
    globalModOverridesState.CollectModOverrides(this);


    return ret;
  }
};
typedef SortMap<dsl::idstring, unsigned int> PropertiesMap;
static_assert(offsetof(PropertiesMap, _data) == 4);
static_assert(offsetof(PropertiesMap, _is_sorted) == 20);
static_assert(offsetof(decltype(PropertiesMap::_data), _data) == 8);


struct FileDataStore {
  virtual ~FileDataStore();
  virtual unsigned int write(__int64, const char*, unsigned int);
  virtual unsigned int read(__int64, char*, unsigned int);
  virtual bool close();
  virtual __int64 size();

  HANDLE _handle;
  PDTH_MSVC2008_string _path;
  _RTL_CRITICAL_SECTION _cs;

  inline static int (FileDataStore::* constructor)(const PDTH_MSVC2008_string* path, DWORD create_mode, DWORD access, DWORD share_mode);
private:
  void create_fake(const PDTH_MSVC2008_string* path, DWORD create_mode, DWORD access, DWORD share_mode)
  {
    (this->*constructor)(path, create_mode, access, share_mode);
  }

public:
  static FileDataStore* create(const std::filesystem::path& path) {
    PDTH_MSVC2008_string path_str = PDTH_MSVC2008_string();
    path_str.assign((char*)path.u8string().c_str(), path.u8string().size()); // FileDataStore's constructor accepts utf8 strings (dsl::utf8_to_wstr gets called before being passed to CreateFileW)

    FileDataStore* ds = (FileDataStore*)diesel_malloc(60);
    memset(ds, 0, 60);

    ds->create_fake(&path_str, OPEN_EXISTING, GENERIC_READ, FILE_SHARE_READ);
    return ds;
  }
};

struct Archive {
  PDTH_MSVC2008_string _name;
  __int64 _start;
  __int64 _size;
  __int64 _pos;
  bool _sizable;
  bool _closed;

  FileDataStore* _ds;
  unsigned int _ds_safepointer;

  inline static int (Archive::* constructor)(const PDTH_MSVC2008_string* name, FileDataStore* ds, __int64 start, __int64 size, bool sizable);

  void create(const std::filesystem::path& file)
  {
    memset(this, 0, sizeof(Archive));

    PDTH_MSVC2008_string name;
    name.assign("");

    auto ds = FileDataStore::create(file);

    //__int64 filesize = std::filesystem::file_size(file);
    auto filesize = ds->size();

    (this->*constructor)(&name, ds, 0, filesize, false);
  }
};
static_assert(sizeof(Archive) == 0x48);

struct TwoLayerTransport {
  X86_THISCALL_HOOK_HELPER_DEFINE_FUNCTION(TwoLayerTransport, open, Archive*, CONCAT_ARGS(Archive* result, unsigned int key)) {
    for (auto& hook : extraTwoLayerTransportHooks) {
      if (hook && hook(result, key))
        return result;
    }

    if (globalModOverridesState.IsOverriden(key)) {

      auto& overrideFile = globalModOverridesState.GetOverride(key);

      if (std::filesystem::exists(overrideFile)) {
        result->create(overrideFile);
        return result;
      }
    }
    if (globalModOverridesState.IsCreatedEntry(key)) {
      auto& createdEntry = globalModOverridesState.GetCreatedEntry(key);

      if (std::filesystem::exists(createdEntry)) {
        result->create(createdEntry);
        return result;
      }
    }
    return (this->*o_open)(result, key);
    
  }
};

#pragma optimize("", off)
DB* globalDb = nullptr;
void ModOverridesState::CollectModOverrides(DB* dieselDb) {
  globalDb = dieselDb;
  auto& data = dieselDb->_data->_lookup._data;
  // Blob loaded arrays get a dummy allocator that will never make allocations.
  // Changing the allocator to the one used to create the array.
  data._allocator = (Allocator*)((char*)dieselDb + 4);

  this->overrides.clear();

  const std::filesystem::path mod_overrides_root = "./assets/mod_overrides";

  if (!std::filesystem::exists(mod_overrides_root))
    return;
  for (std::filesystem::directory_iterator i(mod_overrides_root), end; i != end; ++i) {
    auto& path = i->path();
    if (!std::filesystem::is_directory(path))
      continue;

    for (std::filesystem::recursive_directory_iterator modPathIterator(path), modPathEnd; modPathIterator != modPathEnd; ++modPathIterator) {
      auto& assetsPath = modPathIterator->path();
      if (std::filesystem::is_directory(assetsPath) || !assetsPath.has_extension())
        continue;

      std::filesystem::path pathName = assetsPath;
      pathName.replace_extension();

      auto type = assetsPath.extension().string().substr(1);
      auto name = std::filesystem::relative(pathName, path).u8string();
      std::replace(name.begin(), name.end(), '\\', '/');

      if (type == "dds") {
        type = "texture";
      } else if (type == "bik") {
        type = "movie";
      }

      dsl::idstring type_id = hash64((char*)type.c_str());
      dsl::idstring name_id = hash64((char*)name.c_str());

      auto upper = dieselDb->upper_bound(type_id, name_id);
      auto lower = dieselDb->lower_bound(type_id, name_id);
      
      if (upper == lower)
        continue;

      for (unsigned int lookupIndex = lower; lookupIndex < upper; lookupIndex++) {
        auto& entry = dieselDb->_data->_lookup._data._data[lookupIndex];

        if (entry.first._name._id == name_id._id && entry.first._type._id == type_id._id) {
          this->overrides.insert({ entry.second, assetsPath });
        }
      }

    }

  }
}

#pragma region DB:create_entry and DB:remove_entry
struct lua_State;
void (__cdecl* lua_pushcclosure)(lua_State* L, int(*fn)(lua_State* L), int n);
void (__cdecl* lua_setfield)(lua_State* L, int idx, const char* k);
const char*(__cdecl* lua_tolstring)(lua_State* L, int idx, size_t* len);
void*(__cdecl* lua_touserdata)(lua_State* L, int idx);
int  (__cdecl* lua_type)(lua_State* L, int idx);
#define LUA_TSTRING 4
#define LUA_TUSERDATA 7
#define lua_tostring(L, i) lua_tolstring(L, (i), NULL)

dsl::idstring get_as_idstring_lua(lua_State* L, int idx)
{
  if (lua_type(L, idx) == LUA_TUSERDATA) {
    return *(dsl::idstring*)lua_touserdata(L, idx);
  }
  else if (lua_type(L, idx) == LUA_TSTRING) {
    return hash64(lua_tostring(L, idx));
  }
  else {
    return hash64("");
  }
}

void MainDB__create_entry(dsl::idstring type, dsl::idstring name, const char* path)
{
  std::set<unsigned int> dbKeysToOverwrite;

  if (globalDb->contains(type, name)) {
    auto upper = globalDb->upper_bound(type, name);
    auto lower = globalDb->lower_bound(type, name);

    for (unsigned int lookupIndex = lower; lookupIndex < upper; lookupIndex++) {
      auto& entry = globalDb->_data->_lookup._data._data[lookupIndex];
      if (entry.first._name == name && entry.first._type == type) {
        dbKeysToOverwrite.insert(entry.second);
      }
    }
  }
  else {
    auto& entry = globalDb->add_entry(type, name);
    dbKeysToOverwrite.insert(entry.second);
  }

  for (unsigned int key : dbKeysToOverwrite) {
    globalModOverridesState.LogCreatedEntry(key, path);
  }

}
void MainDB__remove_entry(dsl::idstring type, dsl::idstring name) {
  std::set<unsigned int> dbKeysToRemove;
  std::vector<size_t> indicesToErase;

  if (globalDb->contains(type, name)) {
    auto upper = globalDb->upper_bound(type, name);
    auto lower = globalDb->lower_bound(type, name);

    for (unsigned int lookupIndex = lower; lookupIndex < upper; lookupIndex++) {
      auto& entry = globalDb->_data->_lookup._data._data[lookupIndex];
      if (entry.first._name == name && entry.first._type == type) {
        dbKeysToRemove.insert(entry.second);
        indicesToErase.push_back(lookupIndex);
      }
    }
  }

  std::sort(indicesToErase.begin(), indicesToErase.end(), [](const size_t& a, const size_t& b) {
    return a > b;
    });



  for (auto& key : dbKeysToRemove) {
    globalModOverridesState.LogRemovedEntry(key);
  }
  for (auto index : indicesToErase) {
    globalDb->_data->_lookup._data.erase(index);
  }

}

enum DBCreateEntryNativeErrorCodes : int {
  _NO_ERROR = 0,
  INVALID_PATH = 1,
  PATH_DOES_NOT_EXIST = 2,
  DB_NOT_CREATED = 3
};
__declspec(dllexport) DBCreateEntryNativeErrorCodes __stdcall DBCreateEntry(unsigned long long type, unsigned long long name, const char* path)
{
  if (!path)
    return INVALID_PATH;
  if (!globalDb)
    return DB_NOT_CREATED;
  if (!std::filesystem::exists(path) || std::filesystem::is_directory(path))
    return INVALID_PATH;

  MainDB__create_entry(type, name, path);
  return _NO_ERROR;
}
__declspec(dllexport) DBCreateEntryNativeErrorCodes __stdcall DBRemoveEntry(unsigned long long type, unsigned long long name)
{
  if (!globalDb)
    return DB_NOT_CREATED;
  MainDB__remove_entry(type, name);
  return _NO_ERROR;
}
__declspec(dllexport) bool __stdcall DBHasEntry(unsigned long long type, unsigned long long name)
{
  if (!globalDb)
    return false;
  return globalDb->contains(type, name);
}

__declspec(dllexport) void __stdcall DBReloadOverrideMods()
{
  if (!globalDb)
    return;
  globalModOverridesState.CollectModOverrides(globalDb);
}

int DB_script_create_entry(lua_State* L) {
  // MainDB is first argument, but gets passed as a Diesel WeakPointer reference, so a global is used instead as only one can ever exist
  dsl::idstring type = get_as_idstring_lua(L, 2);
  dsl::idstring name = get_as_idstring_lua(L, 3);
  const char* path = lua_tostring(L, 4);

  if (!path)
    return 0;

  if (!std::filesystem::exists(path) || std::filesystem::is_directory(path))
    return 0;
  MainDB__create_entry(type, name, path);

  return 0;
}
int DB_script_remove_entry(lua_State* L) {
  // MainDB is first argument, but gets passed as a Diesel WeakPointer reference, so a global is used instead as only one can ever exist
  dsl::idstring type = get_as_idstring_lua(L, 2);
  dsl::idstring name = get_as_idstring_lua(L, 3);

  MainDB__remove_entry(type, name);
  return 0;
}

int DB_script_reload_override_mods(lua_State* L)
{
  if (!globalDb)
    return 0;
  globalModOverridesState.CollectModOverrides(globalDb);
  return 0;
}

X86_NONTHISCALL_HOOK_HELPER_DEFINE_FUNCTION(dsl__MainDB__add_members, __cdecl, void, CONCAT_ARGS(lua_State* L)) {
  o_dsl__MainDB__add_members(L);
  lua_pushcclosure(L, DB_script_create_entry, 0);
  lua_setfield(L, -2, "create_entry");
  lua_pushcclosure(L, DB_script_remove_entry, 0);
  lua_setfield(L, -2, "remove_entry");
  lua_pushcclosure(L, DB_script_reload_override_mods, 0);
  lua_setfield(L, -2, "reload_override_mods");
}


void setup_create_entry_hooks() {
  // dsl::MainDB::add_members is too generic to get a signature for
  HOOK_HELPERS_CREATE_HOOK("dsl__MainDB__add_members", ((size_t)GetModuleHandle(gameexecutable) + 0x00389290), h_dsl__MainDB__add_members, &o_dsl__MainDB__add_members);
  //X86_NONTHISCALL_HOOK_HELPER_HOOK_FUNCTION(dsl__MainDB__add_members, "", "");

  GET_FUNCTION(lua_pushcclosure, "\x56\x8B\x74\x24\x00\x8B\x46\x00\x83\x78\x00\x00\x57\x74\x00\xFF\x48\x00\x56\xE8\x00\x00\x00\x00\x83\xC4\x00\x8B\x46\x00\x8B\x48\x00\x3B\x48\x00\x72\x00\x56\xE8\x00\x00\x00\x00\x83\xC4\x00\x8B\x46", "xxxx?xx?xx??xx?xx?xx????xx?xx?xx?xx?x?xx????xx?xx");
  GET_FUNCTION(lua_setfield, "\x8B\x4C\x24\x00\x83\xEC\x00\x53\x56\x8B\x74\x24\x00\x57\x8B\xD6\xE8\x00\x00\x00\x00\x8B\x54\x24\x00\x8B\xF8\x8B\xC2\x8D\x58\x00\x8A\x08\x40\x84\xC9\x75\x00\x2B\xC3\x50\x52\x56\xE8\x00\x00\x00\x00\x89\x44\x24\x00\x8B\x46\x00\x83\xE8", "xxx?xx?xxxxx?xxxx????xxx?xxxxxx?xxxxxx?xxxxxx????xxx?xx?xx");
  GET_FUNCTION(lua_tolstring, "\x56\x8B\x74\x24\x00\x57\x8B\x7C\x24\x00\x8B\xCF\x8B\xD6\xE8\x00\x00\x00\x00\x83\x78", "xxxx?xxxx?xxxxx????xx");
  GET_FUNCTION(lua_touserdata, "\x8B\x4C\x24\x00\x8B\x54\x24\x00\xE8\x00\x00\x00\x00\x8B\x48\x00\x83\xE9", "xxx?xxx?x????xx?xx");
  GET_FUNCTION(lua_type, "\x8B\x4C\x24\x00\x8B\x54\x24\x00\xE8\x00\x00\x00\x00\x3D\x00\x00\x00\x00\x75", "xxx?xxx?x????x????x");
}
#pragma endregion

void setup_modoverrides_mod() {
  if (AttachConsole(ATTACH_PARENT_PROCESS) || AllocConsole())
    freopen("CONOUT$", "w", stdout);

  GET_CLASS_FUNC(CONCAT_ARGS(SortMap<DBExtKey,unsigned int>::lower_bound_index_func), "\x83\xEC\x00\x55\x56\x57\x8B\xF9\x8B\x77\x00\xC7\x44\x24", "xx?xxxxxxx?xxx");
  GET_CLASS_FUNC(CONCAT_ARGS(SortMap<DBExtKey,unsigned int>::upper_bound_index_func), "\x83\xEC\x00\x53\x55\x56\x8B\xF1\x8B\x5E\x00\xC7\x44\x24", "xx?xxxxxxx?xxx");

  GET_CLASS_FUNC(FileDataStore::constructor, "\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x64\x89\x25\x00\x00\x00\x00\x83\xEC\x00\x53\x56\x8B\xF1\x57\x89\x74\x24\x00\x8B\x7C\x24", "x?x????xx????xxxx????xx?xxxxxxxx?xxx");
  GET_CLASS_FUNC(Archive::constructor, "\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x64\x89\x25\x00\x00\x00\x00\x51\x8B\x44\x24\x00\x53\x56\x8B\xF1\x33\xDB\x6A\x00\x53\xC7\x46\x00\x00\x00\x00\x00\x89\x5E\x00\x50\x89\x74\x24\x00\x88\x5E\x00\xE8\x00\x00\x00\x00\x8B\x4C\x24", "x?x????xx????xxxx????xxxx?xxxxxxx?xxx?????xx?xxxx?xx?x????xxx");
  GET_CLASS_FUNC(PDTH_MSVC2008_string::assign_func, "\x56\x8B\x74\x24\x00\x8B\xC6\x57\x8D\x78\x00\xEB\x00\x8D\x49\x00\x8A\x10\x40\x84\xD2\x75\x00\x2B\xC7\x50\x56\xE8", "xxxx?xxxxx?x?xx?xxxxxx?xxxxx");
  GET_CLASS_FUNC(PDTH_MSVC2008_string::assign_func_len, "\x55\x8B\x6C\x24\x00\x56\x57\x8B\xF1\x85\xED", "xxxx?xxxxxx");

  *((size_t*)&diesel_malloc) = (size_t)GetModuleHandle(gameexecutable) + 0x38C270;

  X86_THISCALL_HOOK_HELPER_HOOK_CLASS_FUNCTION(DB, load, "\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x64\x89\x25\x00\x00\x00\x00\x81\xEC\x00\x00\x00\x00\x53\x55\x56\x57\x33\xDB\x53", "x?x????xx????xxxx????xx????xxxxxxx");
  X86_THISCALL_HOOK_HELPER_HOOK_CLASS_FUNCTION(TwoLayerTransport, open, "\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x64\x89\x25\x00\x00\x00\x00\x83\xEC\x00\x56\x8B\xF1\x83\x7E\x00\x00\x57", "x?x????xx????xxxx????xx?xxxxx??x");

  setup_create_entry_hooks();
}

BOOL __stdcall DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
  if (reason == DLL_PROCESS_ATTACH) {
    MH_Initialize();
    setup_modoverrides_mod();
  }
  else if (reason == DLL_PROCESS_DETACH) {
    MH_Uninitialize();
  }

  return TRUE;
}

// Signature scanning code is found below, it is from Payday-2-BLT and is licensed under the MIT license (https://github.com/JamesWilko/Payday-2-BLT/blob/afdc4fc34d23c404765a93024770792ebafaec20/src/signatures/signatures.cpp#L20)
MODULEINFO GetModuleInfo(std::string szModule)
{
  MODULEINFO modinfo = { 0 };
  HMODULE hModule = GetModuleHandle(szModule.c_str());
  if (hModule == 0)
    return modinfo;
  GetModuleInformation(GetCurrentProcess(), hModule, &modinfo, sizeof(MODULEINFO));
  return modinfo;
}
size_t FindPattern(const char* module, const char* funcname, const char* pattern, const char* mask)
{
  MODULEINFO mInfo = GetModuleInfo(module);
  DWORD base = (DWORD)mInfo.lpBaseOfDll;
  DWORD size = (DWORD)mInfo.SizeOfImage;
  DWORD patternLength = (DWORD)strlen(mask);
  for (DWORD i = 0; i < size - patternLength; i++) {
    bool found = true;
    for (DWORD j = 0; j < patternLength; j++) {
      found &= mask[j] == '?' || pattern[j] == *(char*)(base + i + j);
    }
    if (found) {
      //			printf("Found %s: 0x%p\n", funcname, base + i);
      return base + i;
    }
  }
  //printf("Warning: Failed to locate function %s\n", funcname);
  return NULL;
}