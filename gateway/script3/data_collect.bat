@echo off
setlocal

echo --- [MODE] Thu thap Dataset cho nhan: %LABEL_NAME% ---
echo [*] Nhan Ctrl+C de dung chuong trinh.

:: --- 2. Vòng lặp chính ---
:loop
    :: 1. Dump packets (Module 1)
    python dump.py
    
    :: 2. Calculate features (Module 2) - Truyền label vào
    python calculate.py
    
    :: 3. Predict (Bỏ qua hoặc chạy tùy ý bạn)
    python predict2.py 
    
    echo [Loop] Hoan thanh 1 chu ky.
    
    :: Sleep 1 giây (Dùng timeout để thay cho sleep)
    timeout /t 1 /nobreak >nul
    
    :: Quay lại đầu vòng lặp
    goto loop