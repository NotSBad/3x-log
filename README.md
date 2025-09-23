## 3x-Log для Debian 12

## 📦 Обновляем пакеты системы, устанавливаем зависимости:

```bash
apt update && apt upgrade
```

```bash
apt install python3.11-venv
```

## 📁 Клонируем репозиторий и создаем окружение python:
```bash
cd /opt
```

```bash
git clone https://github.com/NotSBad/3x-log.git
```

```bash
cd 3x-log && python3 -m venv .venv
```

## 📦 Активируем окружение и устанавливаем пакеты python:

```bash
source .venv/bin/activate
```

```bash
pip install flask apscheduler bcrypt werkzeug gunicorn
```

## 📄 Копируем service-файл:
```bash
cp 3x-log.service /etc/systemd/system/
```

## 🔄 Перезагружаем настройки systemd:

```bash
systemctl daemon-reload
```

## ✅ Добавляем в автозагрузку:

```bash
systemctl enable 3x-log
```

## ⚡ Запускаем приложение:

```bash
systemctl start 3x-log
```

## ⚠️ Настройка Xray логов:

📋 **Убедитесь, что в конфигурации Xray указаны следующие параметры:**

```json
{
  "log": {
    "loglevel": "debug",
    "access": "/var/log/3x-ui/access.log"
  }
}
```

## 💡 Изменение хеша ADMIN_PASSWORD:

**Для смены пароля администратора используйте онлайн-генератор bcrypt:**

🔗 **Ссылка:** [bcrypt-generator.com](https://bcrypt-generator.com/)

**Шаги:**
1. Откройте [bcrypt-generator.com](https://bcrypt-generator.com/)
2. Введите новый пароль в поле "Text to hash"
3. Скопируйте сгенерированный хеш
4. Обновите переменную `ADMIN_PASSWORD` в конфигурации

## 🔐 Генерация SECRET_KEY

💡 **Как сгенерировать безопасный SECRET_KEY:**

```bash
openssl rand -base64 32
```

## ⚠️ Важно после смены **SECRET_KEY** ♻️ Перезапустите сервис:
    
```bash
systemctl restart 3x-log
```

## 🌐 Приложение будет доступно по адресу:

🔗 [http://127.0.0.1:221](http://127.0.0.1:221/)

📍 Локальный хост: `127.0.0.1:221`
