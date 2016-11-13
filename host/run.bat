@echo off

set LOG=log.txt

time /t >> %LOG%

java -jar InterfaceA3.jar 2>> %LOG%

echo %errorlevel% >> %LOG%
pause