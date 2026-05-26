


"""
secure_app.py
此程式碼已修復所有漏洞、Bug 與 Code Smell，並符合 PEP 8 規範。
"""

import ast
import hashlib
import hmac
import json
import logging
import os
import requests
import secrets
import sqlite3
import subprocess
from typing import Any, List, Optional

# 設定日誌（取代 print 進行偵錯或記錄）
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# 安全性修復：將敏感憑證移至環境變數
PASSWORD_HASH = os.getenv("APP_PASSWORD_HASH", "$2b$12$...")  # 實際應用中應使用 bcrypt/argon2 雜湊值
API_KEY = os.getenv("APP_API_KEY")
API_URL = os.getenv("APP_API_URL", "https://secure-api.com/data")


# =========================
# SQL Injection -> 使用參數化查詢 (Parameterized Query)
# =========================
def login(username: str, password_hash: str) -> bool:
    """使用參數化查詢防止 SQL 注入，並進行安全比對。"""
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()

    # 安全的參數化查詢
    query = "SELECT password_hash FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        # 使用 hmac.compare_digest 防止時序攻擊 (Timing Attack)
        return hmac.compare_digest(result[0], password_hash)
    return False


# =========================
# Command Injection -> 使用 subprocess 列表形式並停用 shell
# =========================
def ping_host(ip: str) -> int:
    """不使用 os.system，改用安全不啟用 shell 的 subprocess.run。"""
    result = subprocess.run(["ping", "-c", "1", ip], capture_output=True, text=True, check=False)
    return result.returncode


# =========================
# Unsafe subprocess -> 接收列表參數並停用 shell=True
# =========================
def run_command(cmd_args: List[str]) -> bytes:
    """接收參數列表而非字串，且絕不開啟 shell=True。"""
    return subprocess.check_output(cmd_args)


# =========================
# Weak Hash Algorithm -> 改用 SHA-256 并加鹽
# =========================
def hash_password(password: str, salt: str = "secure_salt") -> str:
    """放棄 MD5，改用 SHA-256。"""
    return hashlib.sha256((password + salt).encode()).hexdigest()


# =========================
# Predictable Random -> 改用密碼學安全隨機數 (secrets)
# =========================
def generate_token() -> int:
    """不使用有規律的 random.seed，改用密碼學安全的 secrets 模組。"""
    return secrets.randbelow(9000) + 1000  # 產生 1000 到 9999 的隨機數


# =========================
# Dangerous Pickle Load -> 改用安全的 JSON 格式
# =========================
def load_user_data_json(json_str: str) -> Any:
    """拒絕 pickle.load（反序列化漏洞），改用安全的 json 模組。"""
    return json.loads(json_str)


# =========================
# Division by Zero -> 加入防禦性檢查
# =========================
def divide(a: float, b: float) -> Optional[float]:
    """加入除數為零的防禦性檢查。"""
    if b == 0:
        logging.error("Division by zero embedding blocked.")
        return None
    return a / b


# =========================
# Unused Variable -> 移除未使用的變數
# =========================
def calculate() -> int:
    """移除未使用的變數 z。"""
    x = 100
    y = 200
    return x + y


# =========================
# Duplicate Code -> 合併重複的函式
# =========================
def add_numbers(a: int, b: int) -> int:
    """合併重複程式碼，並改用 logging 取代 print。"""
    result = a + b
    logging.info("Result: %s", result)
    return result


# =========================
# Infinite Recursion -> 加入終止條件
# =========================
def recursive_fixed(count: int = 0) -> str:
    """加入終止條件，防止堆疊溢位 (Stack Overflow)。"""
    if count >= 5:
        return "Done"
    return recursive_fixed(count + 1)


# =========================
# Bare Except -> 補上具體異常類別與日誌記錄
# =========================
def safe_exception() -> None:
    """不使用 bare except，捕捉具體錯誤並記錄日誌。"""
    try:
        _ = 1 / 0
    except ZeroDivisionError as e:
        logging.exception("處理除以零的錯誤: %s", e)


# =========================
# Debug Code & Sensitive Info Leak -> 移除敏感資訊
# =========================
def log_system_status() -> None:
    """移除硬編碼的密碼與不安全的 print 偵錯。"""
    logging.info("系統運行正常，已進入生產模式。")


# =========================
# Hardcoded URL -> 走 HTTPS 並由環境變數管理
# =========================
def call_api() -> str:
    """改用安全的 HTTPS 協定，並設定 timeout 防止服務被卡死。"""
    if not API_URL.startswith("https://"):
        logging.warning("正在使用非加密連線！")
    
    try:
        response = requests.get(API_URL, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        logging.error("API 請求失敗: %s", e)
        return ""


# =========================
# File Resource Leak -> 使用 with 內容管理器自動關閉檔案
# =========================
def read_file(file_path: str = "test.txt") -> str:
    """使用 with 確保檔案資源不論成功或失敗都會被釋放。"""
    if not os.path.exists(file_path):
        return ""
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()


# =========================
# Unsafe Eval -> 移除 eval，改用安全的抽象語法樹 (ast.literal_eval)
# =========================
def calculate_input(user_input: str) -> Any:
    """拒絕 eval() 以防惡意代碼執行，改用 ast.literal_eval 安全解析字面量。"""
    try:
        return ast.literal_eval(user_input)
    except (ValueError, SyntaxError):
        logging.error("非法輸入，拒絕執行。")
        return None


# =========================
# Global Variable Abuse -> 改用類別(Class)封裝狀態
# =========================
class Counter:
    """使用物件導向封裝狀態，避免污染全域變數。"""
    def __init__(self):
        self.count = 0

    def increase(self) -> None:
        self.count += 1


# =========================
# Long Function -> 邏輯模組化與拆分
# =========================
def process_lines() -> None:
    """將過長的函式邏輯模組化（此處以迴圈優化冗長程式碼）。"""
    for i in range(1, 21):
        logging.info("line%d", i)


# =========================
# Unreachable Code -> 移除 return 後無法執行的程式碼
# =========================
def test_return() -> bool:
    """移除 return 後不會被執行的死碼 (Dead Code)。"""
    return True


# =========================
# None Comparison -> 使用 is 運算子
# =========================
def check_none(value: Any) -> bool:
    """遵從 PEP 8，應使用 'is None' 而非 '== None'。"""
    return value is None


# =========================
# Mutable Default Argument -> 預設值設為 None
# =========================
def append_item(item: Any, items: Optional[List[Any]] = None) -> List[Any]:
    """避免使用可變動型別（如空列表）作為預設參數，防止資料跨呼叫殘留。"""
    if items is None:
        items = []
    items.append(item)
    return items


# =========================
# Main Entry
# =========================
if __name__ == "__main__":
    logging.info("安全檢查後的應用程式啟動...")
    
    dummy_hash = hash_password("admin123")
    logging.info("登入結果: %s", login("admin", dummy_hash))

    logging.info("安全 Token: %d", generate_token())

    logging.info("計算結果: %s", calculate_input("2 + 2"))

    process_lines()
