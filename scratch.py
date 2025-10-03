# import os
# import shutil
# import sys
#
#
# def get_base_dir():
#     """Определяем папку, где лежит exe или скрипт"""
#     if getattr(sys, "frozen", False):
#         # если запущено как exe через PyInstaller
#         return os.path.dirname(sys.executable)
#     return os.path.dirname(os.path.abspath(__file__))
# def make_writable(path):
#     """Рекурсивно делает все файлы и папки доступными для удаления"""
#     for root, dirs, files in os.walk(path, topdown=False):
#         for name in files:
#             fpath = os.path.join(root, name)
#             try:
#                 os.chmod(fpath, 0o777)
#             except Exception as e:
#                 print(f"[WARN] chmod file {fpath}: {e}")
#         for name in dirs:
#             dpath = os.path.join(root, name)
#             try:
#                 os.chmod(dpath, 0o777)
#             except Exception as e:
#                 print(f"[WARN] chmod dir {dpath}: {e}")
# def remove_readonly(func, path, _):
#     """Снимает атрибут 'только для чтения' на Windows"""
#     os.chmod(path, 0o777)  # Чтение и запись для всех
#     func(path)
# def remove_dir_with_git(clone_dir):
#         # time.sleep(2)
#         """Удаляет указанную директорию, включая папку .git"""
#         if os.path.exists(clone_dir):
#             make_writable(clone_dir)
#             shutil.rmtree(clone_dir, ignore_errors=False)
#
# BASE_DIR = get_base_dir()
# # CONFIG_DIR = os.path.join(BASE_DIR, "collected_files_clear")
# # print(BASE_DIR)
# # print(CONFIG_DIR)
#
# clone_dir = os.path.join(BASE_DIR, "collected_files")
# git_folder = os.path.join(clone_dir, ".git")
# if os.path.exists(git_folder):
#     try:
#         remove_dir_with_git(clone_dir)
#         # shutil.rmtree(git_folder, onerror=remove_readonly)
#         # print("✅ Удалена .git")
#     except Exception as e:
#         print( f"❌ Ошибка при удалении {clone_dir}: {e}")

import re
import ipaddress
import os

# Your EltexACLParser class (unchanged from the previous fix)
class EltexACLParser:
    def __init__(self, config_text):
        self.config_lines = config_text.splitlines()
        self.acls = {}  # {acl_name: [ {source, service, raw}, ... ]}
        self.parse()

    def parse(self):
        current_acl = None
        for line in self.config_lines:
            line = line.strip()
            m = re.match(r'^management access-list (\S+)', line)
            if m:
                current_acl = m.group(1)
                self.acls[current_acl] = []
                continue
            if not current_acl:
                continue
            m = re.match(
                r'^(permit|deny)\s+ip-source\s+(\S+)(?:\s+mask\s+(\S+))?(?:\s+service\s+(\S+))?(?:\s+\S+)?$',
                line
            )
            if m:
                action, ip, mask, service = m.groups()
                if mask:
                    net = str(ipaddress.ip_network((ip, mask), strict=False))
                else:
                    net = str(ipaddress.ip_network(f"{ip}/32", strict=False))
                self.acls[current_acl].append({
                    "action": action,
                    "source": net,
                    "service": service or "any",
                    "raw": line
                })

    def _match(self, ip, network, strict):
        try:
            if strict:
                return ipaddress.ip_network(ip, strict=False) == ipaddress.ip_network(network, strict=False)
            else:
                return ipaddress.ip_address(ip) in ipaddress.ip_network(network, strict=False)
        except ValueError:
            return False

    def find_matches(self, src_ip, dst_ip=None, strict_mode=False):
        matches = set()
        for acl, rules in self.acls.items():
            for rule in rules:
                if src_ip == "any":
                    matches.add(f"{acl}: {rule['raw']}")
                elif self._match(src_ip, rule["source"], strict_mode):
                    matches.add(f"{acl}: {rule['raw']}")
        return matches

    @classmethod
    def from_local_file(cls, filename, src_ip, dst_ip=None,
                        strict_mode=False, base_dir="collected_files", encoding="utf-8"):
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file == filename:
                    with open(os.path.join(root, file), "r", encoding=encoding, errors="ignore") as f:
                        parser = cls(f.read())
                        return parser.find_matches(src_ip, dst_ip, strict_mode)
        return set()

# Test with sample data directly
sample_config = """
management access-list mgmt
 permit ip-source 10.78.4.0 mask 255.255.255.0 oob
 permit ip-source 10.78.26.0 mask 255.255.255.192 oob
 permit ip-source 10.78.83.34 service snmp oob
 permit ip-source 10.78.83.35 service snmp oob
 permit ip-source 10.78.71.4 service ssh oob
 permit ip-source 10.78.71.3 service ssh oob
 permit ip-source 10.26.244.24 service ssh oob
"""

# Simulate file-based test
import tempfile
with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
    temp_file.write(sample_config)
    temp_filename = temp_file.name

# Test the parser
search_text = ["any", "any"]
strict_mode = False
res = EltexACLParser.from_local_file(temp_filename, search_text[0], search_text[1], strict_mode=strict_mode)
print("----Eltex----")
print(f"{os.path.basename(temp_filename)}: \n" + "\n".join(res) + "\n")

# Clean up
os.remove(temp_filename)