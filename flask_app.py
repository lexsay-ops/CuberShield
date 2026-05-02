from flask import Flask, request
import telebot
import os
import json
import base64
import time
import re
from dotenv import load_dotenv
from virustotal_checker import check_url_virustotal, format_vt_result
from cache import get_cached_result, cache_result

# Загружаем переменные окружения (токены)
load_dotenv()
TOKEN = os.getenv("TELEGRAM_TOKEN")
bot = telebot.TeleBot(TOKEN, threaded=False)  # threaded=False ОБЯЗАТЕЛЬНО для PythonAnywhere!

# Удаляем старый вебхук и устанавливаем новый
# URL будет: https://твой_никнейм.pythonanywhere.com/WEBHOOK
# Лучше добавить секретную строку в путь для безопасности
WEBHOOK_SECRET = "kyberpravo2026"  
WEBHOOK_URL = f"https://say.pythonanywhere.com/{WEBHOOK_SECRET}"

# При запуске этого файла установим вебхук
bot.remove_webhook()
time.sleep(1)
bot.set_webhook(url=WEBHOOK_URL)

# Функция извлечения ссылок (такая же как в bot.py)
def extract_urls(text):
    url_pattern = r'https?://[^\s]+'
    return re.findall(url_pattern, text)

# Создаём Flask-приложение
app = Flask(__name__)

# Это обработчик вебхука
@app.route(f'/{WEBHOOK_SECRET}', methods=['POST'])
def webhook():
    # Получаем обновление от Telegram
    update = request.get_json()
    
    # Обрабатываем сообщение (логика как в bot.py)
    if 'message' in update:
        chat_id = update['message']['chat']['id']
        text = update['message'].get('text', '')
        
        if text.startswith('/start'):
            welcome_text = """
🛡️ **КиберЩит: Твоя защита в сети**

Привет! Я бот для проверки подозрительных ссылок через VirusTotal.

🔍 **Что я умею:**
• Проверять ссылки на вирусы и фишинг
• Анализировать результаты более 70 антивирусов
• Давать понятную оценку риска

📨 **Как пользоваться:**
Просто отправь мне ссылку, и я проверю её!

Пример: `https://example.com`

Создано для конкурса #КиберПраво
"""
            bot.send_message(chat_id, welcome_text, parse_mode="Markdown")
        
        else:
            # Проверяем ссылки
            urls = extract_urls(text)
            if not urls:
                bot.send_message(chat_id, "👀 В сообщении не найдено ссылок. Отправь мне ссылку для проверки!")
            else:
                url = urls[0]
                # Отправляем статус "печатает"
                bot.send_chat_action(chat_id, 'typing')
                
                # Проверяем через VirusTotal
                result = check_url_virustotal(url)
                formatted_result = format_vt_result(result)
                bot.send_message(chat_id, formatted_result, parse_mode="Markdown", disable_web_page_preview=True)
    
    return 'OK', 200

# Для локального теста (не обязательно)
@app.route('/')
def index():
    return 'Бот работает!'

if __name__ == '__main__':
    app.run()