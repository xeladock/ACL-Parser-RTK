import os
import sys
import shutil
import subprocess
import re
import tempfile
# from math import trunc
from urllib.parse import quote
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
    if platform['name'] in ('Cisco UCS', 'AlteonOS', 'Citrix MPX', 'IronWare', 'D-Link','Cisco WLC','Cisco Small Business Software','Juniper Junos E-Series'): return None
    return platform['name'] if platform else None
def process_file(file_path, token):
    device_name = os.path.splitext(os.path.basename(file_path))[0]
    platform = get_device_platform(device_name, token)
    return file_path, platform

def main(gitlab_login, gitlab_password, netbox_token, box):
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
    # print(box)
    username = gitlab_login
    safe_password = quote(gitlab_password, safe='')
    # repo_url = "https://configs.net.rt.ru/dc/configs.git"

    # def remove_dir_with_git(rem_dir):
    #     time.sleep(2)
    #     print(rem_dir, "на удаление")
    #     """Удаляет указанную директорию, включая папку .git"""
    #     if os.path.exists(rem_dir):
    #         make_writable(rem_dir)
    #         time.sleep(2)
    #         shutil.rmtree(rem_dir)
    #         time.sleep(1)
    #         # yield(f"Временная папка {clone_dir} успешно удалена.")
    #     # else:
    #     #     yield(f"Папка {clone_dir} не существует.")
    #     yield ("Старт процессов...")
    #     time.sleep(1)
    #     if os.path.exists(rem_dir):
    #         print("папка с файлами есть")
    #         make_writable(rem_dir)
    #         time.sleep(2)
    #         shutil.rmtree(rem_dir)
    #         time.sleep(2)
    #     else:
    #         os.mkdir(rem_dir, 0o755)
    for check in box:
        if check[0]:
            CONFIG_DIR = os.path.join(BASE_DIR, "collected_files_clear", check[1])
            try:
                # 🔹 создаём папку назначения
                if not os.path.exists(CONFIG_DIR):
                    os.makedirs(CONFIG_DIR, exist_ok=True)
                    yield (f"Создана папка для очистки данных {CONFIG_DIR} ")
                    time.sleep(1)
                # helper = f'helper=store --file=/tmp/git-credentials'


                # def git_clone_with_temp_credentials(login, password, repo_url, clone_dir):
                #     # Кроссплатформенное создание временного файла
                #     fd, cred_path = tempfile.mkstemp(prefix="git-cred-", text=True)
                #     os.close(fd)
                #
                #     try:
                #         # Записываем учетку во временный файл
                #         with open(cred_path, "w") as f:
                #             f.write(f"https://{login}:{password}@configs.net.rt.ru\n")
                #
                #         # Удаляем старую директорию, если она есть
                #         if os.path.exists(clone_dir):
                #             shutil.rmtree(clone_dir)
                #
                #         # Запускаем git clone
                #         result = subprocess.run(
                #             [
                #                 "git",
                #                 "-c", f"credential.helper=store --file={cred_path}",
                #                 "clone",
                #                 "--depth=1",
                #                 repo_url,
                #                 clone_dir
                #             ],
                #             text=True,
                #             capture_output=True,
                #         )
                #
                #         return result.stdout, result.stderr, result.returncode
                #
                #     finally:
                #         # Удаляем временный файл (Windows тоже позволяет удалить)
                #         if os.path.exists(cred_path):
                #             os.remove(cred_path)
                # helper, cred_path = tempfile.mkstemp(prefix="git-cred-", text=True)
                # os.close(helper)
                # helper = f'credential.helper=store --file=/tmp/strdtds'
                # password = safe_password
                # пишем учётку в файл
                # try:
                #     os.remove("/tmp/strdtds")
                # except: pass
                # with open(cred_path, "w") as f:
                #             f.write(f"https://{username}:{password}@configs.net.rt.ru\n")
                # with open('/tmp/strdtds', 'w') as f:
                #     f.write(f'https://{username}:{password}@configs.net.rt.ru\n')
                # f.close()


                #
                clone_dir = os.path.join(BASE_DIR, "collected_files",check[1])
                rem_dir = os.path.join(BASE_DIR, "collected_files")
                yield (f"Создана папка для репозитория {clone_dir}")
                time.sleep(1)
                yield (f"Скачиваем файлы {check[1]} с gitlab...")
                time.sleep(1)

                add_url=""
                if check[1] == "ЛВС":
                    add_url = "lan"
                elif check[1] == "ЦОД":
                    add_url = "dc"
                # print(add_url)
                repo_url = f"https://{username}:{safe_password}@configs.net.rt.ru/{add_url}/configs.git"
                # print(repo_url)
                # yield (f"Скачиваем данные...")
                result = subprocess.run(
                    [
                        "git",
                        # "-c", f"credential.helper=store --file={cred_path}",
                        "clone",
                        "--depth=1",
                        repo_url,
                        clone_dir
                    ],
                    text=True,
                    capture_output=True,
                )

                # logs.append(result.stdout)
                # try:
                #     os.remove("/tmp/strdtds")
                # except: pass
                # if os.path.exists(cred_path):
                #     os.remove(cred_path)

                if result.returncode != 0:
                    # yield ("❌ Ошибка при клонировании репозитория.\nПроверьте логин, пароль и токен.")
                    # yield ("DEBUG MODE.")
                    yield (result.stderr.strip())
                    return
                yield (f"Файлы {check[1]} успешно скачаны...")
                time.sleep(1)
                yield (f"Запускаем процесс очистки файлов {check[1]} ... \n-------")
                # 🔹 пример — перенос файлов из репозитория в папку CONFIG_DIR
                for root, dirs, files in os.walk(clone_dir):
                    for file in files:

                        if file.startswith(
                                ("CE", "SZ", "SI", "PR","UF","UK","DV")):
                                # ("PRNG-DC", "DVPR-DC", "SZSP-DC", "CEMO-DC", "CEMS-DC", "UREK-DC", "UFKR-DC", "SINO-DC")):
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

                make_writable(rem_dir)
                time.sleep(2)
                shutil.rmtree(rem_dir)
                time.sleep(1)
                # git_folder = os.path.join(clone_dir, ".git")
                # if os.path.exists(rem_dir):
                #     try:
                #         remove_dir_with_git(rem_dir)
                #         # shutil.rmtree(git_folder, onerror=remove_readonly)
                #         print("✅ Удалена .git")
                #         print(rem_dir)
                #     except Exception as e:
                #         yield f"❌ Ошибка при удалении {clone_dir}: {e}"
                        # print(f"❌ Ошибка при удалении .git: {e}")
                # shutil.rmtree(clone_dir, ignore_errors=True)
                # time.sleep(1)
                make_writable(CONFIG_DIR)
                time.sleep(1)
                yield (f"\n👍 Все файлы {check[1]} успешно скачаны и очищены.")
                # return True
                # return True, logs

            except Exception as e:
                # if 'No such file' or 'FileNotFoundError' in e:
                    # yield (f"\n❌ Не найден установленный git.")
                    yield (e)
        # return False


# if __name__ == "__main__":
#     if len(sys.argv) < 4:
#         print("Использование: python copy_to_local_at_type.py <login> <password> <netbox_token>")
#         sys.exit(1)
#
#     login, password, token = sys.argv[1], sys.argv[2], sys.argv[3]
#     success, logs = main(login, password, token)
#     for line in logs:
#         print(line)
#     sys.exit(0 if success else 1)