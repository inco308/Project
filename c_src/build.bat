@echo off
REM Network Analyzer C Compiler Script
REM Requires MinGW or MSVC

echo Building network_analyzer.exe...

REM Check for gcc
where gcc >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Using GCC...
    gcc -O2 -o ../network_analyzer.exe ^
        common.h hash_map.h hash_map.c ^
        dynamic_array.h dynamic_array.c ^
        csr_graph.h csr_graph.c ^
        csv_reader.h csv_reader.c ^
        analysis.h analysis.c ^
        main.c
    if %ERRORLEVEL% EQU 0 (
        echo Build successful!
        echo Executable: network_analyzer.exe
    ) else (
        echo Build failed!
    )
    goto end
)

REM Check for cl (MSVC)
where cl >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Using MSVC...
    cl /O2 /Fe:../network_analyzer.exe ^
        hash_map.c dynamic_array.c csr_graph.c csv_reader.c analysis.c main.c
    if %ERRORLEVEL% EQU 0 (
        echo Build successful!
        echo Executable: network_analyzer.exe
    ) else (
        echo Build failed!
    )
    goto end
)

echo Error: Neither GCC nor MSVC found!
echo Please install MinGW or Visual Studio.

:end
pause
