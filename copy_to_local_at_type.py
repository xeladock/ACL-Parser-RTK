import os
import sys
import shutil
import subprocess
import re
import requests
import time
# from concurrent.futures import ThreadPoolExecutor, as_completed


def get_base_dir():
    """Определяем папку, где лежит exe или скрипт"""
    if getattr(sys, "frozen", False):
        # если запущено как exe через PyInstaller
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

# def get_base_dir():
#     """
#     Возвращает директорию, где находится исполняемый файл или скрипт.
#     Оптимизировано для Nuitka (--onefile и --standalone) и PyInstaller.
#     """
#     if getattr(sys, 'frozen', False) or hasattr(sys, 'nuitka'):
#         # Скомпилированный режим: Nuitka или PyInstaller
#         if hasattr(sys, 'nuitka') and platform.system() == 'Linux':
#             # Nuitka onefile на Linux: используем sys.argv[0] или /proc/self/exe
#             exe_path = sys.argv[0]
#             try:
#                 # /proc/self/exe для надёжности в sandbox
#                 exe_path = os.path.realpath('/proc/self/exe')
#             except OSError:
#                 pass  # Если /proc/self/exe недоступен, используем sys.argv[0]
#         else:
#             # PyInstaller или Nuitka standalone: sys.executable работает
#             exe_path = sys.executable
#         base_dir = os.path.dirname(os.path.realpath(exe_path))
#         # Отладочный вывод (раскомментируйте для теста)
#         # print(f"sys.argv[0]: {sys.argv[0]}")
#         # print(f"sys.executable: {sys.executable}")
#         # print(f"Executable path (resolved): {exe_path}")
#         # print(f"Base dir (compiled): {base_dir}")
#         return base_dir
#     # Режим разработки: используем путь к текущему скрипту
#     base_dir = os.path.dirname(os.path.abspath(__file__))
#     # print(f"Base dir (dev): {base_dir}")
#     return base_dir


def make_writable(path):
    """Рекурсивно делает все файлы и папки доступными для удаления"""
    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            fpath = os.path.join(root, name)
            try:
                os.chmod(fpath, 0o777)
            except Exception as e:
                yield (f"[WARN] chmod file {fpath}: {e}")
        for name in dirs:
            dpath = os.path.join(root, name)
            try:
                os.chmod(dpath, 0o777)
            except Exception as e:
                yield (f"[WARN] chmod dir {dpath}: {e}")


BASE_DIR = get_base_dir()
CONFIG_DIR = os.path.join(BASE_DIR, "collected_files_clear")


def get_device_platform(device_name, netbox_token):
    # results = []
    # files_to_check = []
    # token = netbox_token
    # # ограничим например 8 потоков, чтобы не штурмовать API
    # with ThreadPoolExecutor(max_workers=8) as executor:
    #     future_map = {executor.submit(process_file, f, token): f for f in files_to_check}
    #     for future in as_completed(future_map):
    #         file_path, platform = future.result()
    #         results.append((file_path, platform))
    #         # опционально: выводим прогресс
    #         print(f"Проверено: {file_path} -> {platform}")

    NETBOX_URL = 'https://netbox.rt.ru/api'

    headers2 = {
        "Authorization": f"Token {netbox_token}",
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (compatible; GitLabParser/1.0)"
    }

    url = f"{NETBOX_URL}/dcim/devices/?name={device_name}"
    response = requests.get(url, headers=headers2, verify=False, timeout=10)
    data = response.json()

    if data['count'] == 0:
        return None

    device = data['results'][0]
    platform = device.get('platform')
    if platform['name'] in ('Cisco UCS', 'AlteonOS', 'Citrix MPX', 'IronWare', 'Cisco WLC'): return None
    return platform['name'] if platform else None
def process_file(file_path, token):
    device_name = os.path.splitext(os.path.basename(file_path))[0]
    platform = get_device_platform(device_name, token)
    return file_path, platform

def main(gitlab_login, gitlab_password, netbox_token):
    """
    Скачивание конфигураций и подготовка структуры папок.
    Возвращает (success, logs)
    """
    # logs = []

    # def make_writable(path):
    #     """Рекурсивно снимает атрибут 'только для чтения' для всех файлов и папок"""
    #     for root, dirs, files in os.walk(path, topdown=False):
    #         for name in files:
    #             file_path = os.path.join(root, name)
    #             os.chmod(file_path, os.stat.S_IWRITE)  # Используем stat.S_IWRITE
    #         for name in dirs:
    #             dir_path = os.path.join(root, name)
    #             os.chmod(dir_path, os.stat.S_IWRITE)  # Используем stat.S_IWRITE

    def remove_dir_with_git(clone_dir):
        time.sleep(2)
        """Удаляет указанную директорию, включая папку .git"""
        if os.path.exists(clone_dir):
            make_writable(clone_dir)
            time.sleep(2)
            shutil.rmtree(clone_dir)
            time.sleep(1)
            # yield(f"Временная папка {clone_dir} успешно удалена.")
        # else:
        #     yield(f"Папка {clone_dir} не существует.")

    try:
        yield ("Старт процессов...")
        time.sleep(1)
        # 🔹 создаём папку назначения
        if not os.path.exists(CONFIG_DIR):
            os.makedirs(CONFIG_DIR, exist_ok=True)
            yield (f"Создана папка для очистки данных {CONFIG_DIR} ")
            time.sleep(1)
        # else:
        #     yield (f"Папка {CONFIG_DIR} уже существует, файлы будут обновлены")

        # пример — клонирование репозитория GitLab
        # замените url_repo и branch на свои
        repo_url = f"https://{gitlab_login}:{gitlab_password}@configs.net.rt.ru/dc/configs.git"

        clone_dir = os.path.join(BASE_DIR, "collected_files")

        yield (f"Создана папка для репозитория {clone_dir}")
        time.sleep(1)
        yield (f"Скачиваем файлы с gitlab...")
        time.sleep(1)
        if os.path.exists(clone_dir):
            shutil.rmtree(clone_dir)
            time.sleep(2)

        # yield (f"Скачиваем данные...")
        result = subprocess.run(
            ["git", "clone", "--depth=1", repo_url, clone_dir]
            # stdout=subprocess.PIPE,
            # stderr=subprocess.STDOUT,
            # text=True
        )
        # logs.append(result.stdout)

        if result.returncode != 0:
            yield ("❌ Ошибка при клонировании репозитория.")
            return
        yield (f"Файлы успешно скачаны...")
        time.sleep(1)
        yield (f"Запускаем процесс очистки файлов... \n-------")
        # 🔹 пример — перенос файлов из репозитория в папку CONFIG_DIR
        for root, dirs, files in os.walk(clone_dir):
            for file in files:

                if file.startswith(
                        ("PRNG-DC", "DVPR-DC", "SZSP-DC", "CEMO-DC", "CEMS-DC", "UREK-DC", "UKFR-DC", "SINO-DC")):
                    src_path = os.path.join(root, file)
                    device_name = os.path.splitext(file)[0]

                    # определяем платформу через NetBox
                    platform = get_device_platform(device_name, netbox_token)

                    if not platform or not platform.strip():
                        continue

                    platform = platform.replace("/", os.sep)
                    platform = re.sub(r'[<>:"/\\|?*]', '_', platform)
                    platform_dir = os.path.join(CONFIG_DIR, platform)
                    os.makedirs(platform_dir, exist_ok=True)

                    dst_path = os.path.join(platform_dir, file)

                    shutil.copy2(src_path, dst_path)
                    yield (f"✅ [{platform}] → {dst_path}")
        # 🔹 чистим временную папку
        time.sleep(2)
        git_folder = os.path.join(clone_dir, ".git")
        if os.path.exists(git_folder):
            try:
                remove_dir_with_git(clone_dir)
                # shutil.rmtree(git_folder, onerror=remove_readonly)
                # print("✅ Удалена .git")
            except Exception as e:
                yield f"❌ Ошибка при удалении {clone_dir}: {e}"
                # print(f"❌ Ошибка при удалении .git: {e}")
        # shutil.rmtree(clone_dir, ignore_errors=True)

        yield ("\n✅ Все файлы успешно скачаны и очищены.")
        # return True, logs

    except Exception as e:
        yield (f"\n❌ Ошибка: {e}")
        # return False, logs


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Использование: python copy_to_local_at_type.py <login> <password> <netbox_token>")
        sys.exit(1)

    login, password, token = sys.argv[1], sys.argv[2], sys.argv[3]
    success, logs = main(login, password, token)
    for line in logs:
        print(line)
    sys.exit(0 if success else 1)