from abc import ABC, abstractmethod
import ipaddress


class BaseParser(ABC):
    def __init__(self, config_text):
        self.config = config_text
        self.lines = config_text.splitlines()
        self.object_ranges = self.parse_object_ranges()
    @abstractmethod
    def get_object_group(self, group_name):
        pass


# ================================
# Cisco IOS
# ================================

# class CiscoASAParser(BaseParser):
#     class CiscoASAParser:
#
#         def __init__(self, config_text):
#             self.config = config_text
#             self.lines = config_text.splitlines()
#
#         def get_object_group(self, group_name):
#             """Возвращает список объектов только этой группы"""
#             group_start = None
#             objects = []
#
#             for i, line in enumerate(self.lines):
#                 if line.strip() == f"object-group network {group_name}":
#                     group_start = i
#                     break
#
#             if group_start is None:
#                 return []
#
#             for line in self.lines[group_start + 1:]:
#                 if not line.startswith(" "):
#                     break
#                 line = line.strip()
#                 parts = line.split()
#                 if line.startswith("network-object"):
#
#                     # network-object host 10.1.1.1
#                     if parts[1] == "host":
#                         ip = parts[2]
#                         objects.append({
#                             "text": line,
#                             "type": "host",
#                             "network": ipaddress.ip_network(ip + "/32")
#                         })
#                     # network-object 10.1.1.1
#                     elif len(parts) == 2 and self._is_ip(parts[1]):
#                         ip = parts[1]
#                         objects.append({
#                             "text": line,
#                             "type": "host",
#                             "network": ipaddress.ip_network(ip + "/32")
#                         })
#                     # network-object 10.1.1.0 255.255.255.0
#                     elif len(parts) == 3 and self._is_ip(parts[1]):
#                         ip = parts[1]
#                         mask = parts[2]
#                         net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
#                         objects.append({
#                             "text": line,
#                             "type": "network",
#                             "network": net
#                         })
#                     # network-object obj_name (ссылка на object network)
#                     elif len(parts) == 2:
#                         objects.append({
#                             "text": line,
#                             "type": "object_ref",
#                             "name": parts[1]
#                         })
#             return objects
#
#         def check_ip(self, objects, ip):
#             """Проверяет IP, подсвечивая строки с попаданием"""
#             target = ipaddress.ip_address(ip)
#             result = []
#
#             for obj in objects:
#                 if obj["type"] in ["host", "network"]:
#                     if target in obj["network"]:
#                         result.append((obj["text"], True))
#                     else:
#                         result.append((obj["text"], False))
#                 elif obj["type"] == "object_ref":
#                     # Не раскрываем range, просто выводим имя жирным, если пользователь IP совпадает
#                     # Можно позже добавить проверку по внешнему словарю, но по умолчанию False
#                     result.append((obj["text"], False))
#             return result
#
#         def _is_ip(self, s):
#             try:
#                 ipaddress.ip_address(s)
#                 return True
#             except ValueError:
#                 return False
#import ipaddress

class CiscoASAParser:

    def __init__(self, config_text):
        self.config = config_text
        self.lines = config_text.splitlines()
        self.object_ranges = self.parse_object_ranges()

    def parse_object_ranges(self):
        obj_ranges = {}

        i = 0
        while i < len(self.lines):
            line = self.lines[i].strip()

            if line.startswith("object network"):
                parts = line.split()
                name = parts[2]

                if i + 1 < len(self.lines):
                    next_line = self.lines[i + 1].strip()

                    if next_line.startswith("range"):
                        r = next_line.split()

                        start = ipaddress.ip_address(r[1])
                        end = ipaddress.ip_address(r[2])

                        obj_ranges[name] = (start, end)

            i += 1

        return obj_ranges

    def get_object_group(self, group_name):
        """Возвращает список объектов только этой группы"""
        group_start = None
        objects = []

        for i, line in enumerate(self.lines):
            if line.strip() == f"object-group network {group_name}":
                group_start = i
                break

        if group_start is None:
            return []

        for line in self.lines[group_start + 1:]:
            if not line.startswith(" "):
                break
            line = line.strip()
            parts = line.split()
            if line.startswith("network-object"):

                # network-object host 10.1.1.1
                if parts[1] == "host":
                    ip = parts[2]
                    objects.append({
                        "text": line,
                        "type": "host",
                        "network": ipaddress.ip_network(ip + "/32")
                    })
                # network-object 10.1.1.1
                elif len(parts) == 2 and self._is_ip(parts[1]):
                    ip = parts[1]
                    objects.append({
                        "text": line,
                        "type": "host",
                        "network": ipaddress.ip_network(ip + "/32")
                    })
                # network-object 10.1.1.0 255.255.255.0
                elif len(parts) == 3 and self._is_ip(parts[1]):
                    ip = parts[1]
                    mask = parts[2]
                    net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                    objects.append({
                        "text": line,
                        "type": "network",
                        "network": net
                    })
                # network-object obj_name (ссылка на object network)
                elif len(parts) == 2:
                    objects.append({
                        "text": line,
                        "type": "object_ref",
                        "name": parts[1]
                    })
                elif len(parts) == 3 and parts[1] == "object":
                    objects.append({
                        "text": line,
                        "type": "object_ref",
                        "name": parts[2]
                    })
        return objects

    def check_ip(self, objects, ip):
        """Проверяет IP, подсвечивая строки с попаданием"""
        target = ipaddress.ip_address(ip)
        result = []

        for obj in objects:
            if obj["type"] in ["host", "network"]:
                if target in obj["network"]:
                    result.append((obj["text"], True))
                else:
                    result.append((obj["text"], False))
            elif obj["type"] == "object_ref":

                name = obj["name"]

                if name in self.object_ranges:

                    start, end = self.object_ranges[name]

                    if start <= target <= end:
                        result.append((obj["text"], True))
                    else:
                        result.append((obj["text"], False))

                else:
                    # если нет range — просто не матчим
                    result.append((obj["text"], False))
                # Не раскрываем range, просто выводим имя жирным, если пользователь IP совпадает
                # Можно позже добавить проверку по внешнему словарю, но по умолчанию False
                # result.append((obj["text"], False))
        return result

    def _is_ip(self, s):
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False
# class CiscoASAParser(BaseParser):
#
#     def get_object_group(self, group_name):
#
#         group_start = None
#         objects = []
#
#         for i, line in enumerate(self.lines):
#
#             if line.strip() == f"object-group network {group_name}":
#                 group_start = i
#                 break
#
#         if group_start is None:
#             return []
#
#         for line in self.lines[group_start + 1:]:
#
#             if not line.startswith(" "):
#                 break
#
#             line = line.strip()
#
#             if line.startswith("network-object"):
#
#                 parts = line.split()
#
#                 # network-object host 10.1.1.1
#                 if parts[1] == "host":
#                     objects.append(parts[2] + "/32")
#
#                 # network-object 10.1.1.1
#                 elif len(parts) == 2:
#                     objects.append(parts[1] + "/32")
#
#                 # network-object 10.1.1.0 255.255.255.0
#                 elif len(parts) == 3:
#
#                     ip = parts[1]
#                     mask = parts[2]
#
#                     net = ipaddress.IPv4Network(
#                         f"{ip}/{mask}",
#                         strict=False
#                     )
#
#                     objects.append(str(net))
#
#         return objects


# ================================
# Huawei VRP
# ================================

class HuaweiVRPParser(BaseParser):

    def get_object_group(self, group_name):

        # будет реализовано позже
        return []


# ================================
# Juniper
# ================================

class JuniperParser(BaseParser):

    def get_object_group(self, group_name):

        # будет реализовано позже
        return []