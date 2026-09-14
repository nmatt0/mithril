cmake_minimum_required(VERSION 3.20)
project(mithril VERSION 0.2.1 LANGUAGES CXX)

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
  src/derkey.cpp
  src/binver.cpp
  src/filever.cpp
  src/inflate.cpp
  src/kconfig.cpp
  src/kconfig_infer.cpp
  src/kallsyms.cpp
  src/kernelcve.cpp
  src/kernelfeed.cpp
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
  src/fdt.cpp
  src/boot.cpp
  src/bootkeys.cpp
  src/certid.cpp
  src/pubkey.cpp
  src/bigint.cpp
  src/keyweak.cpp
  src/keycorpus.cpp
  src/keys.cpp
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
  src/derkey.cpp
  src/binver.cpp
  src/filever.cpp
  src/inflate.cpp
  src/kconfig.cpp
  src/kconfig_infer.cpp
  src/kallsyms.cpp
  src/kernelcve.cpp
  src/kernelfeed.cpp
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
  src/fdt.cpp
  src/boot.cpp
  src/bootkeys.cpp
  src/certid.cpp
  src/pubkey.cpp
  src/bigint.cpp
  src/keyweak.cpp
  src/keycorpus.cpp
  src/keys.cpp
)
target_include_directories(mithril_unit PRIVATE src)

# Test/maintenance helper: normalized-JSON -> compact binary OSV index. Used by
# tests/test_cve.py to build a fixture .mdb without reimplementing the format.
add_executable(mkosvindex tests/mkosvindex.cpp src/osvindex.cpp)
target_include_directories(mkosvindex PRIVATE src)

enable_testing()
add_test(NAME mithril_unit COMMAND mithril_unit)

# The Python drivers are the bulk of the regression gate (per-detector
# identify/extract checks over synthetic corpora), mirroring tests/run.sh. Most
# take the built binary path as argv[1]; test_boot and the two generator
# consistency checks take none. Each self-skips cleanly (exit 0) when an
# optional tool (e.g. openssl) is absent, so they are safe to register
# unconditionally. They need a Python 3 interpreter; without one only
# mithril_unit above is run.
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
  # Corpus/generator consistency checks and test_boot: no binary argument.
  add_test(NAME gen_bootkeys
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/gen_bootkeys.py --check
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
  add_test(NAME gen_keycorpus
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/gen_keycorpus.py --check
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
  add_test(NAME test_boot
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_boot.py
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
  # These take the freshly built binary as argv[1].
  set(_mithril_py_tests
    test_secrets
    test_der_keys
    test_keys
    test_sbom
    test_cve
    test_licenses
    test_kconfig
    test_kconfig_recovery
    test_kernelfeed
  )
  foreach(_t IN LISTS _mithril_py_tests)
    add_test(
      NAME ${_t}
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/${_t}.py $<TARGET_FILE:mithril>
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
  endforeach()
endif()

include(GNUInstallDirs)
install(TARGETS mithril RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES mithril.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1 OPTIONAL)
