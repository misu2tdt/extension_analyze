@echo off
setlocal enabledelayedexpansion

REM === Batch test script cho nhieu CRX samples ===
REM Chay tung sample trong sandbox, luu output rieng theo ten sample

set SANDBOX_IMAGE=extanalyze-sandbox:latest
set SAMPLES_DIR=%cd%\..\malware_samples
set RESULTS_DIR=%cd%\batch_results
set TIMEOUT=60

if not exist "%RESULTS_DIR%" mkdir "%RESULTS_DIR%"

echo ========================================
echo  BATCH TEST - Extension Dynamic Analysis
echo ========================================
echo.

REM Duyet qua tung file .crx trong thu muc samples
for %%F in ("%SAMPLES_DIR%\*.crx") do (
    set SAMPLE_NAME=%%~nF
    set OUT_DIR=%RESULTS_DIR%\!SAMPLE_NAME!

    echo [*] Testing: %%~nxF
    if not exist "!OUT_DIR!" mkdir "!OUT_DIR!"

    docker run --rm --shm-size=2g --cap-add=NET_ADMIN --cap-add=NET_RAW ^
        -v "%SAMPLES_DIR%:/samples" ^
        -v "!OUT_DIR!:/work/output" ^
        %SANDBOX_IMAGE% ^
        "/samples/%%~nxF" /work/output %TIMEOUT%

    echo [+] Done: %%~nxF - output tai !OUT_DIR!
    echo ----------------------------------------
    echo.
)

echo ========================================
echo  BATCH TEST COMPLETE
echo  Ket qua trong: %RESULTS_DIR%
echo ========================================