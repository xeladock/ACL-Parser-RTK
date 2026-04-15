import ipaddress
import os
from unpack_group_parser import CiscoASAParser, HuaweiVRPParser


BASE_DIR = "config_files_clear"


def find_device_config(device):

    for root, dirs, files in os.walk(BASE_DIR):

        for f in files:

            if f == device:
                return os.path.join(root, f)

    return None


VENDOR_MAP = {
    "Cisco ASA": CiscoASAParser,
    "Huawei VRP": HuaweiVRPParser
}

def detect_vendor(path):

    if "Cisco ASA" in path:
        return "cisco_asa"
    if "Huawei VRP" in path:
        return "huawei_vrp"
    return None
def get_object_group(device, group):

    path = find_device_config(device)

    if not path:
        return None, None, "Выберите устройство"

    vendor = detect_vendor(path)

    with open(path, encoding="utf8", errors="ignore") as f:
        config = f.read()

    if vendor == "cisco_asa":
        parser = CiscoASAParser(config)

    else:
        return None, None, "Unsupported vendor"

    objects = parser.get_object_group(group)

    return parser, objects, None


# def get_object_group(device, group):
#     path = find_device_config(device)
#     print(path)
#     if not path:
#         return None, "Device not found"
#     vendor = detect_vendor(path)
#     with open(path, encoding="utf8", errors="ignore") as f:
#         config = f.read()
#     if vendor == "cisco_asa":
#         parser = CiscoASAParser(config)
#     elif vendor == "huawei_vrp":
#         parser = HuaweiVRPParser(config)
#     else:
#         return None, "Unsupported vendor"
#     objects = parser.get_object_group(group)
#     return objects, None

