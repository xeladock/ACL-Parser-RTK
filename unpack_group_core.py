import ipaddress
import os
from unpack_group_parser import CiscoASAParser, CiscoIOSXEParser, CiscoFirepowerParser, CiscoNexusParser, CiscoPIXParser

BASE_DIR = "config_files_clear"


def find_device_config(device):

    for root, dirs, files in os.walk(BASE_DIR):

        for f in files:

            if f == device:
                return os.path.join(root, f)

    return None


# VENDOR_MAP = {
#     "Cisco ASA": CiscoASAParser,
#     "Cisco IOS XE": CiscoIOSXEParser,
#     "Cisco FXOS": CiscoFirepowerParser,
#     "Cisco NX-OS": CiscoNexusParser,
#
# }

def detect_vendor(path):

    if "Cisco ASA" in path:
        return "cisco_asa"
    if "Cisco IOS XE" in path:
        return "cisco_ios_xe"
    if "Cisco FXOS" in path:
        return "cisco_fxos"
    if "Cisco NX-OS" in path:
        return "cisco_nxos"
    if "Cisco PIX" in path:
        return "cisco_pix"
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
    elif vendor == "cisco_ios_xe":
        parser = CiscoIOSXEParser(config)
    elif vendor == "cisco_fxos":
        parser = CiscoFirepowerParser(config)
    elif vendor == "cisco_nxos":
        parser = CiscoNexusParser(config)
    elif vendor == "cisco_pix":
        parser = CiscoPIXParser(config)


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

