add_library(bkcrack-testrunner)
target_sources(bkcrack-testrunner
    PUBLIC FILE_SET HEADERS
    FILES
        TestRunner.hpp
    PRIVATE
        TestRunner.cpp
        main.cpp
)
target_enable_warnings(bkcrack-testrunner)
target_compile_features(bkcrack-testrunner PUBLIC cxx_std_20)
