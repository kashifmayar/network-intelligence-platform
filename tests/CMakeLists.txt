add_executable(nip_tests
    ByteReaderTest.cpp)
target_link_libraries(nip_tests PRIVATE nip_parse GTest::gtest_main)
nip_set_warnings(nip_tests)
if(MINGW)
    # Keep the test executable runnable without the MinGW bin directory on PATH.
    target_link_options(nip_tests PRIVATE -static)
endif()
include(GoogleTest)
gtest_discover_tests(nip_tests DISCOVERY_MODE PRE_TEST)
