@echo off
setlocal

:: --- 1. Xử lý tham số đầu vào (Label) ---
:: Mặc định là "Unknown" nếu không nhập tham số
set "LABEL_NAME=MiTM"
if not "%~1"=="" set "LABEL_NAME=%~1"

echo --- [MODE] Thu thap Dataset cho nhan: %LABEL_NAME% ---
echo [*] Nhan Ctrl+C de dung chuong trinh.

:: --- 2. Vòng lặp chính ---
:loop
    :: 1. Dump packets (Module 1)
    python dump_packets_2.py
    
    :: 2. Calculate features (Module 2) - Truyền label vào
    python calculate_features_2.py "%LABEL_NAME%"
    
    :: 3. Predict (Bỏ qua hoặc chạy tùy ý bạn)
    :: python final.py 
    
    echo [Loop] Hoan thanh 1 chu ky.
    
    :: Sleep 1 giây (Dùng timeout để thay cho sleep)
    timeout /t 1 /nobreak >nul
    
    :: Quay lại đầu vòng lặp
    goto loop