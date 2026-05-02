import telebot
import os
import re
import hashlib
from dotenv import load_dotenv
from virustotal_checker import check_url_virustotal, format_vt_result, check_file_virustotal, format_file_result

load_dotenv()
TOKEN = os.getenv("TELEGRAM_TOKEN")
bot = telebot.TeleBot(TOKEN)

# Удаляем вебхук, если он был (для локальной работы)
bot.remove_webhook()

def extract_urls(text):
    url_pattern = r'https?://[^\s]+'
    return re.findall(url_pattern, text)

@bot.message_handler(commands=['start'])
def send_welcome(message):
    welcome_text = """
🛡️ **КиберЩит: Твоя защита в сети**

Привет! Я бот для проверки подозрительных ссылок и файлов через VirusTotal.

🔍 **Что я умею:**
• Проверять ссылки на вирусы и фишинг
• Проверять файлы (до 32 МБ) — просто отправь мне файл!
• Анализировать результаты более 70 антивирусов
• Давать понятную оценку риска

📨 **Как пользоваться:**
• Отправь ссылку — я проверю её
• Отправь файл — я проверю его

Создано для конкурса #КиберПраво
"""
    bot.reply_to(message, welcome_text, parse_mode="Markdown")

# Обработчик текстовых сообщений (ссылки)
@bot.message_handler(func=lambda message: True, content_types=['text'])
def handle_text(message):
    text = message.text
    urls = extract_urls(text)
    
    if not urls:
        bot.reply_to(message, "👀 В сообщении не найдено ссылок. Отправь мне ссылку или файл для проверки!")
        return
    
    url = urls[0]
    bot.send_chat_action(message.chat.id, 'typing')
    status_msg = bot.reply_to(message, f"🔍 Проверяю ссылку: {url}\nЭто может занять несколько секунд...")
    
    try:
        result = check_url_virustotal(url)
        formatted_result = format_vt_result(result)
        bot.edit_message_text(
            chat_id=message.chat.id,
            message_id=status_msg.message_id,
            text=formatted_result,
            parse_mode="Markdown",
            disable_web_page_preview=True
        )
    except Exception as e:
        bot.edit_message_text(
            chat_id=message.chat.id,
            message_id=status_msg.message_id,
            text=f"❌ Произошла ошибка при проверке: {str(e)}\nПопробуй позже."
        )

# Обработчик документов (файлов)
@bot.message_handler(content_types=['document'])
def handle_document(message):
    try:
        # Получаем информацию о файле
        file_info = bot.get_file(message.document.file_id)
        file_name = message.document.file_name
        file_size = message.document.file_size
        
        # Проверяем размер файла (бесплатный API VirusTotal ограничен 32 МБ)
        MAX_FILE_SIZE = 32 * 1024 * 1024  # 32 МБ
        if file_size > MAX_FILE_SIZE:
            bot.reply_to(message, f"❌ Файл слишком большой! Максимальный размер для проверки: 32 МБ. Твой файл: {file_size / 1024 / 1024:.1f} МБ")
            return
        
        # Сообщаем о начале проверки
        bot.send_chat_action(message.chat.id, 'typing')
        status_msg = bot.reply_to(message, f"📥 Скачиваю файл: {file_name} ({file_size / 1024:.1f} КБ)...")
        
        # Скачиваем файл во временную папку
        downloaded_file = bot.download_file(file_info.file_path)
        
        # Создаём временную папку, если её нет
        temp_dir = "temp_files"
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)
        
        # Сохраняем файл временно
        temp_path = os.path.join(temp_dir, file_name)
        with open(temp_path, 'wb') as f:
            f.write(downloaded_file)
        
        # Обновляем сообщение
        bot.edit_message_text(
            chat_id=message.chat.id,
            message_id=status_msg.message_id,
            text=f"🔍 Анализирую файл: {file_name}\nЭто может занять некоторое время..."
        )
        
        # Проверяем файл через VirusTotal
        result = check_file_virustotal(temp_path, file_name)
        formatted_result = format_file_result(result)
        
        # Удаляем временный файл
        os.remove(temp_path)
        
        # Отправляем результат
        bot.edit_message_text(
            chat_id=message.chat.id,
            message_id=status_msg.message_id,
            text=formatted_result,
            parse_mode="Markdown"
        )
        
    except Exception as e:
        bot.reply_to(message, f"❌ Ошибка при обработке файла: {str(e)}")

if __name__ == "__main__":
    print("🤖 Бот запущен...")
    bot.infinity_polling()