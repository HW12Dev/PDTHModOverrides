target("VERSION")
  set_kind("shared")
  set_languages("cxx20")

  add_files("./main.cpp", "./version.def")

  set_symbols("debug")

target_end()