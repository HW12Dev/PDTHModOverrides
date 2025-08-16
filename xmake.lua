--add_requires("wxwidgets 3.2.0")
add_requires("minhook")

includes("version_proxy")

set_runtimes("MD")

target("PDTHModOverrides")
  set_kind("shared")
  set_languages("cxx20")
  set_exceptions("cxx")

  set_symbols("debug")

  --add_packages("wxwidgets")



  add_packages("minhook")
  --add_defines("__WXMSW__", "WXUSINGDLL")

  add_files("./src/*.cpp")
  add_headerfiles("./src/*.h")
  add_includedirs("./src/")
target_end()