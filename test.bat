cd "%~dp0"
setlocal enabledelayedexpansion
set limit=0
echo:Config is !CONFIGURATION!
if !CONFIGURATION!==Debug set limit=3
if !CONFIGURATION!==Release set limit=100
if !limit!==0 goto bad
for /L %%x in (1, 1, !limit!) do (
   echo:Run number %%x
   "src\!CONFIGURATION!\mytest.exe"
   if errorlevel 1 goto fail
)
goto :eof
:bad
echo:Bad value for %%CONFIGURATION%%
exit /b 1
:fail
set q=!ERRORLEVEL!
echo:Test failed with error !q!
exit /b !q!
