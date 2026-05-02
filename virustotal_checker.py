import requests
import os
import time
import json
import base64
import hashlib
from dotenv import load_dotenv
from cache import get_cached_result, cache_result

load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# ================== Функции для проверки ССЫЛОК ==================

def check_url_virustotal(url):
    """Проверяет URL через VirusTotal (синхронно)"""
    print(f"\n🔍 Начинаем проверку URL: {url}")

    # Проверяем кэш
    cached = get_cached_result(url)
    if cached:
        print("📦 Результат взят из кэша")
        return cached

    # Нормализуем URL
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        print(f"🔧 Нормализованный URL: {url}")

    headers = {"x-apikey": VT_API_KEY, "Accept": "application/json"}

    try:
        # Кодируем URL для запроса
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        print(f"🆔 URL ID (base64): {url_id}")

        # 1. Пытаемся получить существующий отчёт
        get_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        print(f"📡 GET-запрос к: {get_url}")
        response = requests.get(get_url, headers=headers)

        if response.status_code == 200:
            print("✅ Отчёт найден!")
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            result = {
                "harmless": stats.get("harmless", 0),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "timeout": stats.get("timeout", 0),
                "total": sum(stats.values()),
                "permalink": f"https://www.virustotal.com/gui/url/{url_id}"
            }
            cache_result(url, result)
            return result

        elif response.status_code == 404:
            print("❌ Отчёт не найден (404). Отправляем на сканирование...")
            # 2. Отправляем URL на сканирование
            scan_url = "https://www.virustotal.com/api/v3/urls"
            data = {"url": url}
            scan_response = requests.post(scan_url, headers=headers, data=data)

            if scan_response.status_code != 200:
                return {"error": f"Ошибка отправки URL: {scan_response.status_code}"}

            scan_result = scan_response.json()
            analysis_id = scan_result.get("data", {}).get("id")
            if not analysis_id:
                return {"error": "Не удалось получить ID анализа"}

            # 3. Ждём завершения анализа (до 60 секунд)
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            max_attempts = 20  # 20 * 3 = 60 секунд
            for attempt in range(max_attempts):
                print(f"⏳ Попытка {attempt+1}/{max_attempts}: проверяем статус анализа...")
                time.sleep(3)
                analysis_response = requests.get(analysis_url, headers=headers)
                if analysis_response.status_code != 200:
                    continue
                analysis_data = analysis_response.json()
                status = analysis_data.get("data", {}).get("attributes", {}).get("status")
                print(f"📊 Статус анализа: {status}")
                if status == "completed":
                    print("✅ Анализ завершён!")
                    stats = analysis_data.get("data", {}).get("attributes", {}).get("stats", {})
                    result = {
                        "harmless": stats.get("harmless", 0),
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "undetected": stats.get("undetected", 0),
                        "timeout": stats.get("timeout", 0),
                        "total": sum(stats.values()),
                        "permalink": f"https://www.virustotal.com/gui/url/{url_id}"
                    }
                    cache_result(url, result)
                    return result

            # Если вышли из цикла — анализ не завершился
            return {"error": "Анализ занял слишком много времени. Попробуйте позже или проверьте ссылку на сайте VirusTotal."}

        else:
            return {"error": f"Ошибка API: {response.status_code}"}

    except Exception as e:
        return {"error": f"Не удалось проверить ссылку: {str(e)}"}


def format_vt_result(result):
    """Форматирует результат проверки ссылки для отправки пользователю"""
    if "error" in result:
        return f"❌ {result['error']}"

    malicious = result.get("malicious", 0)
    suspicious = result.get("suspicious", 0)
    harmless = result.get("harmless", 0)
    total = result.get("total", 0)

    if malicious > 0:
        verdict = "🔴 **ОПАСНО!**"
        risk_level = "Высокий риск"
    elif suspicious > 0:
        verdict = "🟡 **ПОДОЗРИТЕЛЬНО**"
        risk_level = "Средний риск"
    else:
        verdict = "🟢 **БЕЗОПАСНО**"
        risk_level = "Низкий риск"

    message = f"""
{verdict}

📊 **Результаты проверки VirusTotal:**
• Обнаружено угроз: {malicious}
• Подозрительных: {suspicious}
• Безопасных: {harmless}
• Не обнаружено: {result.get('undetected', 0)}

📈 Всего антивирусов проверили: {total}
🔗 [Посмотреть полный отчёт]({result.get('permalink', '#')})

#{risk_level} #КиберПраво
"""
    return message


# ================== Функции для проверки ФАЙЛОВ ==================

def calculate_file_hash(file_path):
    """Вычисляет SHA-256 хеш файла"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def check_file_virustotal(file_path, original_filename):
    """
    Проверяет файл через VirusTotal
    Сначала по хешу, если не найден — загружает файл
    """
    print(f"\n🔍 Начинаем проверку файла: {original_filename}")

    file_hash = calculate_file_hash(file_path)
    print(f"🔑 SHA-256 хеш: {file_hash}")

    # Проверяем кэш
    cached = get_cached_result(file_hash)
    if cached:
        print("📦 Результат взят из кэша")
        cached["filename"] = original_filename
        return cached

    headers = {"x-apikey": VT_API_KEY, "Accept": "application/json"}

    try:
        # 1. Пытаемся найти файл по хешу
        file_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        print(f"📡 Поиск файла по хешу...")
        response = requests.get(file_url, headers=headers)

        if response.status_code == 200:
            print("✅ Файл уже есть в базе VirusTotal")
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            result = {
                "filename": original_filename,
                "hash": file_hash,
                "harmless": stats.get("harmless", 0),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "timeout": stats.get("timeout", 0),
                "total": sum(stats.values()),
                "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
                "scan_date": attributes.get("last_analysis_date", ""),
                "meaningful_name": attributes.get("meaningful_name", original_filename)
            }

            cache_result(file_hash, result)
            return result

        elif response.status_code == 404:
            print("❌ Файл не найден в базе. Загружаем на анализ...")

            # Проверяем размер файла (бесплатный API ограничен 32 МБ)
            file_size = os.path.getsize(file_path)
            if file_size > 32 * 1024 * 1024:
                return {
                    "error": f"Файл слишком большой для загрузки через бесплатный API (макс. 32 МБ)",
                    "filename": original_filename
                }

            # 2. Загружаем файл на VirusTotal
            upload_url = "https://www.virustotal.com/api/v3/files"
            with open(file_path, "rb") as f:
                files = {"file": (original_filename, f)}
                upload_response = requests.post(upload_url, headers=headers, files=files)

            if upload_response.status_code != 200:
                return {
                    "error": f"Ошибка загрузки файла: {upload_response.status_code}",
                    "filename": original_filename
                }

            upload_data = upload_response.json()
            analysis_id = upload_data.get("data", {}).get("id")
            print(f"🆔 Получен analysis_id: {analysis_id}")

            # 3. Ждём завершения анализа (до 60 секунд)
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            max_attempts = 20  # 20 * 3 = 60 секунд
            for attempt in range(max_attempts):
                print(f"⏳ Попытка {attempt+1}/{max_attempts}: проверяем статус анализа...")
                time.sleep(3)
                analysis_response = requests.get(analysis_url, headers=headers)
                if analysis_response.status_code != 200:
                    continue
                analysis_data = analysis_response.json()
                status = analysis_data.get("data", {}).get("attributes", {}).get("status")
                print(f"📊 Статус анализа: {status}")
                if status == "completed":
                    print("✅ Анализ завершён!")
                    stats = analysis_data.get("data", {}).get("attributes", {}).get("stats", {})
                    result = {
                        "filename": original_filename,
                        "hash": file_hash,
                        "harmless": stats.get("harmless", 0),
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "undetected": stats.get("undetected", 0),
                        "timeout": stats.get("timeout", 0),
                        "total": sum(stats.values()),
                        "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
                        "scan_date": int(time.time())
                    }
                    cache_result(file_hash, result)
                    return result

            # Если вышли из цикла — анализ не завершился
            return {
                "error": "Анализ занял слишком много времени. Попробуйте позже или проверьте файл на сайте VirusTotal.",
                "filename": original_filename
            }

        else:
            return {
                "error": f"Ошибка API: {response.status_code}",
                "filename": original_filename
            }

    except Exception as e:
        return {
            "error": f"Не удалось проверить файл: {str(e)}",
            "filename": original_filename
        }


def format_file_result(result):
    """Форматирует результат проверки файла для отправки пользователю"""
    if "error" in result:
        return f"❌ **Ошибка проверки файла**\n\nФайл: `{result.get('filename', 'неизвестно')}`\nОшибка: {result['error']}"

    filename = result.get("filename", "неизвестно")
    malicious = result.get("malicious", 0)
    suspicious = result.get("suspicious", 0)
    harmless = result.get("harmless", 0)
    total = result.get("total", 0)

    if malicious > 0:
        if malicious >= 5:
            verdict = "🔴 **ОПАСНО! Множественные обнаружения**"
        else:
            verdict = "🟠 **ВНИМАНИЕ! Обнаружены угрозы**"
        risk_level = "Высокий риск"
    elif suspicious > 0:
        verdict = "🟡 **ПОДОЗРИТЕЛЬНО**"
        risk_level = "Средний риск"
    else:
        verdict = "🟢 **БЕЗОПАСНО**"
        risk_level = "Низкий риск"

    message = f"""
{verdict}

📄 **Файл:** `{filename}`
🔑 **SHA-256:** `{result.get('hash', '')[:16]}...`

📊 **Результаты проверки VirusTotal:**
• Обнаружено угроз: {malicious}
• Подозрительных: {suspicious}
• Безопасных: {harmless}
• Не обнаружено: {result.get('undetected', 0)}

📈 Всего антивирусов проверили: {total}
🔗 [Посмотреть полный отчёт]({result.get('permalink', '#')})

#{risk_level} #КиберПраво
"""
    return message