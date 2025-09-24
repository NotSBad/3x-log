import re
import sqlite3
import os
import glob
import gzip
import time
import hashlib
from flask import Flask, send_from_directory, render_template, request, session, Response
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
import bcrypt
import logging
import threading

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_prefix=1)

# Настройка логирования - только ошибки
logging.basicConfig(filename='/var/log/3x-ui/app.log', level=logging.WARNING)

# Безопасное получение обязательных переменных окружения
app.secret_key = os.environ['SECRET_KEY']
ADMIN_USERNAME = os.environ['ADMIN_USERNAME']
ADMIN_PASSWORD_HASH = os.environ['ADMIN_PASSWORD_HASH']

# Проверка секретного ключа
if app.secret_key == 'dev-key-change-in-production':
    raise ValueError("SECRET_KEY must be set to a secure random value in production")

# Проверка формата хэша пароля
if not ADMIN_PASSWORD_HASH.startswith('$2b$') and not ADMIN_PASSWORD_HASH.startswith('$2a$'):
    raise ValueError("Invalid password hash format - must be bcrypt")

DB_FILE = '/opt/3x-log/logs.db'
LOG_DIR = '/var/log/3x-ui/'
LOG_PATTERN = r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+) from ([\d.:]+) accepted (([^:]+):([^\s]+)) \[[^\]]+\] email: (\S+)'
LAST_OFFSET_FILE = '/opt/3x-log/last_offset.txt'
ITEMS_PER_PAGE = 50

# Блокировка для синхронизации доступа к базе данных
db_lock = threading.Lock()

# Время последнего обновления логов
last_log_update_time = 0
LOG_UPDATE_INTERVAL = 30  # секунд между обновлениями логов при запросах

# Декоратор для проверки авторизации
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            auth = request.authorization
            if not auth or not auth.username or not auth.password:
                return Response('Please provide login and password', 401,
                                {'WWW-Authenticate': 'Basic realm="Login Required"'})
            if (auth.username == ADMIN_USERNAME and
                bcrypt.checkpw(auth.password.encode('utf-8'), ADMIN_PASSWORD_HASH.encode('utf-8'))):
                session['username'] = auth.username
            else:
                return Response('Invalid credentials', 401,
                                {'WWW-Authenticate': 'Basic realm="Login Required"'})
        return f(*args, **kwargs)
    return decorated_function

# ---------------- БАЗА ДАННЫХ ----------------
def init_db():
    with db_lock:
        try:
            conn = sqlite3.connect(DB_FILE, timeout=60)
            cursor = conn.cursor()

            # Проверяем существование старой таблицы
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs'")
            old_table_exists = cursor.fetchone() is not None

            if old_table_exists:
                cursor.execute("PRAGMA table_info(logs)")
                columns = [column[1] for column in cursor.fetchall()]
                if 'source_ip' not in columns:
                    logging.warning("Обнаружена старая структура таблицы. Выполняем миграцию...")
                    migrate_old_to_new_structure(conn, cursor)
            else:
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        source_ip TEXT,
                        source_port INTEGER,
                        protocol TEXT,
                        destination_host TEXT,
                        destination_port INTEGER,
                        user TEXT,
                        original_destination TEXT,
                        UNIQUE(timestamp, source_ip, source_port, original_destination, user)
                    )
                ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS processed_files (
                    file_name TEXT PRIMARY KEY,
                    hash TEXT,
                    last_modified REAL
                )
            ''')

            cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_user ON logs(user)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON logs(source_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_dest_host ON logs(destination_host)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_dest_port ON logs(destination_port)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_composite ON logs(timestamp, user, source_ip, destination_host)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_timestamp_desc ON logs(timestamp DESC)')

            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"Ошибка в init_db: {e}")
            if 'conn' in locals():
                conn.rollback()
                conn.close()

def migrate_old_to_new_structure(conn, cursor):
    try:
        cursor.execute('''
            CREATE TABLE logs_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_ip TEXT,
                source_port INTEGER,
                protocol TEXT,
                destination_host TEXT,
                destination_port INTEGER,
                user TEXT,
                original_destination TEXT,
                UNIQUE(timestamp, source_ip, source_port, original_destination, user)
            )
        ''')

        cursor.execute('SELECT timestamp, ip_port, destination, user FROM logs')
        old_records = cursor.fetchall()

        migrated_count = 0
        for record in old_records:
            timestamp, ip_port, original_destination, user = record
            source_ip = ip_port
            source_port = None
            if ':' in ip_port:
                try:
                    source_ip, port_str = ip_port.rsplit(':', 1)
                    source_port = int(port_str)
                except ValueError:
                    source_ip = ip_port
                    source_port = None

            protocol = None
            destination_host = original_destination
            destination_port = None
            if original_destination.startswith('tcp:') or original_destination.startswith('udp:'):
                try:
                    protocol, dest_host_port = original_destination.split(':', 1)
                    destination_host = dest_host_port
                    if ':' in dest_host_port:
                        destination_host, port_str = dest_host_port.rsplit(':', 1)
                        try:
                            destination_port = int(port_str)
                        except ValueError:
                            destination_port = None
                    else:
                        if protocol.lower() == 'tcp':
                            destination_port = 443
                        elif protocol.lower() == 'udp':
                            destination_port = 53
                except ValueError:
                    protocol = None
                    destination_host = original_destination

            cursor.execute('''
                INSERT OR IGNORE INTO logs_new
                (timestamp, source_ip, source_port, protocol, destination_host, destination_port, user, original_destination)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, source_ip, source_port, protocol, destination_host, destination_port, user, original_destination))

            migrated_count += 1

        cursor.execute('DROP TABLE logs')
        cursor.execute('ALTER TABLE logs_new RENAME TO logs')
        conn.commit()
        logging.warning(f"Миграция завершена. Перенесено записей: {migrated_count}")
    except Exception as e:
        logging.error(f"Ошибка при миграции: {e}")
        conn.rollback()
        raise

def get_metadata(key, default=None):
    with db_lock:
        try:
            conn = sqlite3.connect(DB_FILE, timeout=60)
            cursor = conn.cursor()
            cursor.execute('SELECT value FROM metadata WHERE key = ?', (key,))
            result = cursor.fetchone()
            conn.close()
            return result[0] if result else default
        except Exception as e:
            logging.error(f"Ошибка в get_metadata: {e}")
            return default

def set_metadata(key, value):
    with db_lock:
        try:
            conn = sqlite3.connect(DB_FILE, timeout=60)
            cursor = conn.cursor()
            cursor.execute('INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)', (key, value))
            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"Ошибка в set_metadata: {e}")
            if 'conn' in locals():
                conn.rollback()
                conn.close()

# ---------------- ОБРАБОТКА ЛОГОВ ----------------
def get_file_hash(file_path):
    hasher = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        logging.error(f"Ошибка при вычислении хэша файла {file_path}: {e}")
        return None

def parse_and_insert_logs(incremental=True):
    global last_log_update_time
    with db_lock:
        try:
            conn = sqlite3.connect(DB_FILE, timeout=60)
            cursor = conn.cursor()

            log_files = sorted(glob.glob(os.path.join(LOG_DIR, 'access.log*')), key=os.path.getmtime)

            for log_file in log_files:
                file_name = os.path.basename(log_file)
                last_modified = os.path.getmtime(log_file)

                cursor.execute('SELECT hash, last_modified FROM processed_files WHERE file_name = ?', (file_name,))
                result = cursor.fetchone()

                if result:
                    prev_hash, prev_mtime = result
                    if last_modified == prev_mtime and (log_file.endswith('.gz') or prev_hash == get_file_hash(log_file)):
                        continue
                    if not log_file.endswith('.gz') and file_name == 'access.log' and incremental:
                        process_current_log_incremental(log_file, cursor)
                    else:
                        process_file(log_file, cursor)
                    new_hash = get_file_hash(log_file) if not log_file.endswith('.gz') else None
                    cursor.execute('UPDATE processed_files SET hash = ?, last_modified = ? WHERE file_name = ?',
                                   (new_hash, last_modified, file_name))
                else:
                    process_file(log_file, cursor)
                    new_hash = get_file_hash(log_file) if not log_file.endswith('.gz') else None
                    cursor.execute('INSERT INTO processed_files (file_name, hash, last_modified) VALUES (?, ?, ?)',
                                   (file_name, new_hash, last_modified))

            conn.commit()
            conn.close()
            last_log_update_time = time.time()
        except Exception as e:
            logging.error(f"Ошибка в parse_and_insert_logs: {e}")
            if 'conn' in locals():
                conn.rollback()
                conn.close()

def process_current_log_incremental(log_file, cursor):
    last_offset = 0
    if os.path.exists(LAST_OFFSET_FILE):
        try:
            with open(LAST_OFFSET_FILE, 'r') as f:
                last_offset = int(f.read().strip())
        except (ValueError, FileNotFoundError):
            last_offset = 0

    try:
        file_size = os.path.getsize(log_file)
        if last_offset > file_size:
            last_offset = 0
            with open(LAST_OFFSET_FILE, 'w') as f:
                f.write('0')

        with open(log_file, 'r') as file:
            file.seek(last_offset)
            for line in file:
                process_line(line, cursor)
            new_offset = file.tell()
            with open(LAST_OFFSET_FILE, 'w') as f:
                f.write(str(new_offset))
    except Exception as e:
        logging.error(f"Ошибка при инкрементальной обработке файла {log_file}: {e}")

def process_file(log_file, cursor):
    try:
        if log_file.endswith('.gz'):
            with gzip.open(log_file, 'rt') as file:
                for line in file:
                    process_line(line, cursor)
        else:
            with open(log_file, 'r') as file:
                for line in file:
                    process_line(line, cursor)
    except Exception as e:
        logging.error(f"Ошибка при обработке файла {log_file}: {e}")

def process_line(line, cursor):
    if 'from 127.0.0.1' in line:
        return False

    match = re.match(LOG_PATTERN, line.strip())
    if match:
        timestamp = match.group(1)
        ip_port = match.group(2)
        original_destination = match.group(3)
        protocol = match.group(4)
        dest_host_port = match.group(5)
        user = match.group(6)

        source_ip = ip_port
        source_port = None
        if ':' in ip_port:
            try:
                source_ip, port_str = ip_port.rsplit(':', 1)
                source_port = int(port_str)
            except ValueError:
                source_ip = ip_port
                source_port = None

        destination_host = dest_host_port
        destination_port = None
        if ':' in dest_host_port:
            try:
                destination_host, port_str = dest_host_port.rsplit(':', 1)
                destination_port = int(port_str)
            except ValueError:
                destination_host = dest_host_port
                destination_port = None
        else:
            if protocol.lower() == 'tcp':
                destination_port = 443
            elif protocol.lower() == 'udp':
                destination_port = 53

        cursor.execute('''
            INSERT OR IGNORE INTO logs
            (timestamp, source_ip, source_port, protocol, destination_host, destination_port, user, original_destination)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, source_ip, source_port, protocol, destination_host, destination_port, user, original_destination))
        return True
    return False

def auto_clear_old_logs():
    with db_lock:
        try:
            conn = sqlite3.connect(DB_FILE, timeout=60)
            cursor = conn.cursor()

            one_month_ago = datetime.now() - timedelta(days=30)
            one_month_ago_str = one_month_ago.strftime('%Y/%m/%d %H:%M:%S.%f')

            cursor.execute('SELECT COUNT(*) FROM logs WHERE timestamp < ?', (one_month_ago_str,))
            count_to_delete = cursor.fetchone()[0]

            batch_size = 500
            total_deleted = 0
            while True:
                cursor.execute('DELETE FROM logs WHERE timestamp < ? LIMIT ?', (one_month_ago_str, batch_size))
                deleted_count = cursor.rowcount
                total_deleted += deleted_count
                conn.commit()
                if deleted_count < batch_size:
                    break

            set_metadata('last_clear_time', str(time.time()))
            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"Ошибка при автоочистке логов: {e}")
            if 'conn' in locals():
                conn.rollback()
                conn.close()

def get_unique_users():
    with db_lock:
        try:
            conn = sqlite3.connect(DB_FILE, timeout=60)
            cursor = conn.cursor()
            cursor.execute('SELECT DISTINCT user FROM logs ORDER BY user')
            users = [row[0] for row in cursor.fetchall()]
            conn.close()
            return users
        except Exception as e:
            logging.error(f"Ошибка в get_unique_users: {e}")
            return []

def get_logs(user_filter=None, ip_filter=None, dest_filter=None, page=1):
    with db_lock:
        try:
            conn = sqlite3.connect(DB_FILE, timeout=60)
            cursor = conn.cursor()

            query_count = 'SELECT COUNT(*) FROM logs WHERE 1=1'
            params_count = []

            if user_filter:
                query_count += ' AND user = ?'
                params_count.append(user_filter)

            if ip_filter:
                query_count += ' AND (source_ip LIKE ? OR CAST(source_port AS TEXT) LIKE ?)'
                params_count.extend([f'%{ip_filter}%', f'%{ip_filter}%'])

            if dest_filter:
                query_count += ' AND (destination_host LIKE ? OR CAST(destination_port AS TEXT) LIKE ? OR protocol LIKE ?)'
                params_count.extend([f'%{dest_filter}%', f'%{dest_filter}%', f'%{dest_filter}%'])

            cursor.execute(query_count, params_count)
            total_items = cursor.fetchone()[0]
            total_pages = max(1, (total_items + ITEMS_PER_PAGE - 1) // ITEMS_PER_PAGE)

            query = '''
                SELECT timestamp, source_ip, source_port, protocol,
                       destination_host, destination_port, user, original_destination
                FROM logs WHERE 1=1
            '''
            params = []

            if user_filter:
                query += ' AND user = ?'
                params.append(user_filter)

            if ip_filter:
                query += ' AND (source_ip LIKE ? OR CAST(source_port AS TEXT) LIKE ?)'
                params.extend([f'%{ip_filter}%', f'%{ip_filter}%'])

            if dest_filter:
                query += ' AND (destination_host LIKE ? OR CAST(destination_port AS TEXT) LIKE ? OR protocol LIKE ?)'
                params.extend([f'%{dest_filter}%', f'%{dest_filter}%', f'%{dest_filter}%'])

            query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
            params.extend([ITEMS_PER_PAGE, (page - 1) * ITEMS_PER_PAGE])

            cursor.execute(query, params)
            logs = []
            for row in cursor.fetchall():
                logs.append({
                    'timestamp': row[0],
                    'source_ip': row[1],
                    'source_port': row[2],
                    'protocol': row[3].upper() if row[3] else 'N/A',
                    'destination_host': row[4],
                    'destination_port': row[5],
                    'user': row[6],
                    'original_destination': row[7]
                })

            conn.close()
            start_page = max(1, page - 2)
            end_page = min(total_pages + 1, page + 3)
            page_range = range(start_page, end_page)

            return logs, total_pages, page_range
        except Exception as e:
            logging.error(f"Ошибка в get_logs: {e}")
            return [], 1, range(1, 2)

# ---------------- МАРШРУТЫ ----------------
@app.route('/', methods=['GET', 'POST'])
@login_required
def display_logs():
    # Обновляем логи только если прошло больше 30 секунд с последнего обновления
    global last_log_update_time
    current_time = time.time()

    if current_time - last_log_update_time > LOG_UPDATE_INTERVAL:
        parse_and_insert_logs(incremental=True)

    user_filter = request.args.get('user')
    ip_filter = request.args.get('ip')
    dest_filter = request.args.get('dest')

    try:
        page = max(1, int(request.args.get('page', 1)))
    except ValueError:
        page = 1

    logs, total_pages, page_range = get_logs(user_filter, ip_filter, dest_filter, page)
    users = get_unique_users()
    current_user = session.get('username', 'Guest')

    return render_template('logs.html', logs=logs, users=users,
                           selected_user=user_filter, ip_filter=ip_filter,
                           dest_filter=dest_filter, current_page=page,
                           total_pages=total_pages, page_range=page_range,
                           current_user=current_user,
                           items_per_page=ITEMS_PER_PAGE)

@app.route('/favicon.<ext>')
def favicon(ext):
    if ext not in ['ico', 'png']:
        return "Not found", 404

    mimetypes = {
        'ico': 'image/x-icon',
        'png': 'image/png'
    }

    filename = f'favicon.{ext}'
    if os.path.exists(os.path.join(app.static_folder, filename)):
        return send_from_directory(app.static_folder, filename, mimetype=mimetypes.get(ext))
    else:
        return "Not found", 404

@app.route('/logout')
def logout():
    session.pop('username', None)
    return Response('Logged out', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

# ---------------- СОЗДАНИЕ ПРИЛОЖЕНИЯ ----------------
def create_app():
    init_db()

    scheduler = BackgroundScheduler()
    scheduler.add_job(func=parse_and_insert_logs, args=(True,), trigger="interval", minutes=5)
    scheduler.add_job(func=auto_clear_old_logs, trigger="interval", hours=24)
    scheduler.start()

    return app
