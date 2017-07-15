cd "%~dp0"
setlocal enabledelayedexpansion
set limit=3
if !CONFIGURATION!=="Release" set limit=100
for /L %%x in (0, 1, !CONFIGURATION!) do (
   echo:Run number %%x
   "src\!CONFIGURATION!\mytest.exe" 2>&1
)
