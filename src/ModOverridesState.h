#pragma once

#include <map>
#include <filesystem>

namespace dsl { struct idstring; }

struct DB;

class ModOverridesState {
public:
  void CollectModOverrides(DB* dieselDb);

  bool IsOverriden(unsigned int dbKey) const { return overrides.contains(dbKey); }

  const std::filesystem::path& GetOverride(unsigned int dbKey) const { return overrides.find(dbKey)->second; }

  void AddOverride(unsigned int dbKey, const std::filesystem::path& path) { overrides.insert({ dbKey, path }); }

  void LogCreatedEntry(unsigned int dbKey, const std::filesystem::path& path) { createdEntries_Paths.insert(std::make_pair(dbKey, path)); }
  void LogRemovedEntry(unsigned int dbKey) { if (createdEntries_Paths.contains(dbKey)) createdEntries_Paths.erase(dbKey); }
  bool IsCreatedEntry(unsigned int dbKey) const { return createdEntries_Paths.contains(dbKey); }
  const std::filesystem::path& GetCreatedEntry(unsigned int dbKey) { return createdEntries_Paths.find(dbKey)->second; }

private:
  std::map<unsigned int, std::filesystem::path> overrides;
  std::map<unsigned int, std::filesystem::path> createdEntries_Paths;
};