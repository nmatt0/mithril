cmake_minimum_required(VERSION 3.20)
project(mithril VERSION 0.1.3 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

# Optional sanitizers for debug builds: cmake -DMT_SANITIZE=ON
option(MT_SANITIZE "Build with ASan+UBSan" OFF)
if(MT_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=address,undefined)
endif()

add_executable(mithril
  src/main.cpp
  src/ahocorasick.cpp
  src/validators.cpp
  src/rules_builtin.cpp
  src/engine.cpp
  src/userrules.cpp
  src/credstore.cpp
  src/binver.cpp
  src/filever.cpp
  src/inflate.cpp
  src/kconfig.cpp
  src/kconfig_infer.cpp
  src/kallsyms.cpp
  src/kernelcve.cpp
  src/langmanifest.cpp
  src/rpm.cpp
  src/version.cpp
  src/dbpath.cpp
  src/cve.cpp
  src/osvindex.cpp
  src/cveupdate.cpp
  src/sha256.cpp
  src/license.cpp
  src/sbom.cpp
  src/sbom_emit.cpp
  src/walk.cpp
  src/json.cpp
  src/human.cpp
)
target_include_directories(mithril PRIVATE src)
target_compile_definitions(mithril PRIVATE MITHRIL_VERSION="${PROJECT_VERSION}")

find_package(Threads REQUIRED)
target_link_libraries(mithril PRIVATE Threads::Threads)

# Component unit tests for the engine primitives + the secrets detectors.
add_executable(mithril_unit
  tests/unit/unit_tests.cpp
  src/ahocorasick.cpp
  src/validators.cpp
  src/rules_builtin.cpp
  src/engine.cpp
  src/userrules.cpp
  src/credstore.cpp
  src/binver.cpp
  src/filever.cpp
  src/inflate.cpp
  src/kconfig.cpp
  src/kconfig_infer.cpp
  src/kallsyms.cpp
  src/kernelcve.cpp
  src/langmanifest.cpp
  src/rpm.cpp
  src/version.cpp
  src/dbpath.cpp
  src/cve.cpp
  src/osvindex.cpp
  src/sha256.cpp
  src/license.cpp
  src/sbom.cpp
  src/sbom_emit.cpp
)
target_include_directories(mithril_unit PRIVATE src)

# Test/maintenance helper: normalized-JSON -> compact binary OSV index. Used by
# tests/test_cve.py to build a fixture .mdb without reimplementing the format.
add_executable(mkosvindex tests/mkosvindex.cpp src/osvindex.cpp)
target_include_directories(mkosvindex PRIVATE src)

include(GNUInstallDirs)
install(TARGETS mithril RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES mithril.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1 OPTIONAL)
