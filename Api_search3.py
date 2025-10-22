import os
import sys
import requests
from urllib3.exceptions import InsecureRequestWarning
from collections import defaultdict
from class_resolver import (CiscoNexusParser, HuaweiParser, JuniperACLParser, FortiOSParser,
                            CiscoIOSXEParser, CiscoIOSParser, EltexACLParser, CiscoASAParser3
)

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

output_dir = "collected_files_clear"

PREFIX_LABELS = {
    "Волга": "PRNG-DC",
    "Дальний Восток": "DVPR-DC",
    "Северо-Запад": "SZSP-DC",
    "Центр": "CEMO-DC",
    "Корпоративный Центр": "CEMS-DC",
    "Урал": "UREK-DC",
    "Юг": "UKFR-DC",
    "Сибирь": "SINO-DC",
}


def region(vv):
    region_name = next(
        (label for label, prefix in PREFIX_LABELS.items() if vv.startswith(prefix))
    )
    return region_name

def main(src_ip, dst_ip, allowed_prefixes=None, allowed_platforms=None, strict_mode=False):
    if not os.path.exists(output_dir):
        yield  ["❌ Папка с конфигурациями не найдена"]
        return

    search_text = [src_ip, dst_ip]
    dd = defaultdict(list)

    # скан папки
    for root, dirs, files in os.walk(output_dir):
        for file in files:
            if allowed_prefixes and not any(file.startswith(pref) for pref in allowed_prefixes):
                continue
            dd[root.split(os.sep)[-1]].append(file)

    results = []
    # print(dd)
    # --- парсинг по платформам ---
    for k, v in dd.items():
        if allowed_platforms and k not in allowed_platforms:
            continue
        if k == 'FortiOS':
            # print(k ,v)
            for vv in v:
                res = FortiOSParser.from_local_file(vv, search_text[0], search_text[1],strict_mode=strict_mode)
                # print(res)
                if res:
                    yield(f"----{k} {region(vv)}----")
                    yield(vv + ": \n" + "\n".join(res) + "\n")
        if k in ('Cisco ASA', 'Cisco FXOS', 'Cisco PIX'):
            # print(k ,v)
            for vv in v:
                res = CiscoASAParser3.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
                if res:
                    yield(f"----{k} {region(vv)}----")
                    yield(vv + ": \n" + "\n".join(res) + "\n")

        if k in ('Cisco IOS','B4COM BCOM-OS-DC','EdgeCore','IBM_Lenovo Network OS','HP ProCurve','Dell Networking OS') :
            for vv in v:
                res = CiscoIOSParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
                if res:
                    yield(f"----{k} {region(vv)}----")
                    yield(vv + ": \n" + "\n".join(res) + "\n")
        if k in ('Cisco IOS XE','Cisco IOS XR'):
            for vv in v:
                # print(vv)
                res = CiscoIOSXEParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
                # print(res)
                if res:
                    yield(f"----{k} {region(vv)}----")
                    yield(vv + ": \n" + "\n".join(res) + "\n")
        if k == 'Cisco NX-OS':
            for vv in v:
                res = CiscoNexusParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
                if res:
                    yield(f"----{k} {region(vv)}----")
                    yield(vv + ": \n" + "\n".join(res) + "\n")

        if k == 'Huawei VRP':
            for vv in v:
                res = HuaweiParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
                if res:
                    yield(f"----{k} {region(vv)}----")
                    yield(vv + ": \n" + "\n".join(res) + "\n")

        if k == 'Juniper Junos':
            for vv in v:
                res = JuniperACLParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
                if res:
                    yield(f"----{k} {region(vv)}----")
                    yield(vv + ": \n" + "\n".join(res) + "\n")
        if k == 'Eltex':
            for vv in v:
                res = EltexACLParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
                if res:
                    yield(f"----{k} {region(vv)}----")
                    yield(vv + ": \n" + "\n".join(res) + "\n")

    return results


# if __name__ == "__main__":
#     if len(sys.argv) < 3:
#         print("Использование: python Api-search3.py <src_ip> <dst_ip> [prefix1 prefix2 ...] [--platforms ...]")
#         sys.exit(1)
#
#     src_ip, dst_ip = sys.argv[1], sys.argv[2]
#
#     if "--platforms" in sys.argv:
#         idx = sys.argv.index("--platforms")
#         allowed_prefixes = sys.argv[3:idx]
#         allowed_platforms = sys.argv[idx + 1:]
#     else:
#         allowed_prefixes = sys.argv[3:]
#         allowed_platforms = None
#
#     res = main(src_ip, dst_ip, allowed_prefixes, allowed_platforms)
#     for line in res:
#         print(line)