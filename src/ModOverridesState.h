#pragma once

#include <map>
#include <filesystem>

struct DB;

class ModOverridesState {
public:
  void CollectModOverrides(DB* dieselDb);

  bool IsOverriden(unsigned int dbKey) const { return overrides.contains(dbKey); }

  const std::filesystem::path& GetOverride(unsigned int dbKey) const { return overrides.find(dbKey)->second; }

  void AddOverride(unsigned int dbKey, const std::filesystem::path& path) { overrides.insert({ dbKey, path }); }

private:
  std::map<unsigned int, std::filesystem::path> overrides;
};