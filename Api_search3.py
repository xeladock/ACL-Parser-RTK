import os
import sys
import requests
from urllib3.exceptions import InsecureRequestWarning
from collections import defaultdict
from class_resolver import (CiscoNexusParser, JuniperACLParser, FortiOSParser,
                            CiscoIOSXEParser, CiscoIOSParser, EltexACLParser, CiscoASAParser3, EltexESRParser,
                            HPEParser, HuaweiParser3
                            )

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

output_dir = "config_files_clear"

# PREFIX_LABELS = {
#     "(Волга)": "PRNG-DC",
#     "(Дальний Восток)": "DV",
#     "(Северо-Запад)": "SZSP-DC",
#     "(Центр)": "CEMO-DC",
#     "(Корпоративный Центр)": "CEMS-DC",
#     "(Урал)": "UREK-DC",
#     "(Юг)": "UFKR-DC",
#     "(Сибирь)": "SI",
# }

PREFIX_LABELS = {
    "(Корпоративный Центр)": "CE",
    "(Центр)": "CE",
    "(Волга)": "PR",
    "(Дальний Восток)": "DV",
    "(Северо-Запад)": "SZ",
    "(Урал)": "UR",
    "(Юг)": "UF",
    "(Сибирь)": "SI",
}


def region(vv):
    region_name = next(
        (label for label, prefix in PREFIX_LABELS.items() if vv.startswith(prefix))
    )
    # print(vv)
    return region_name

def main(src_ip, dst_ip, allowed_prefixes=None, allowed_platforms=None, allowed_ues=None, strict_mode=False):
    if not os.path.exists(output_dir):
        yield  ["❌ Папка с конфигурациями не найдена"]
        return

    search_text = [src_ip, dst_ip]
    dd = defaultdict(list)

    # скан папки
    for root, dirs, files in os.walk(output_dir):
        # print(root)
        parts = root.split(os.sep)

        if root == output_dir and allowed_ues:
            dirs[:] = [d for d in dirs if d in allowed_ues]
            continue

        # пропускаем корень collected_files_clear
        if len(parts) < 3:
            continue

        loc = parts[-2]  # ЛВС / ЦОД
        pl = parts[-1]  # платформа

        # --- ФИЛЬТР УЭС ---
        if allowed_ues and loc not in allowed_ues:
            continue
        # print(loc)
        for file in files:
            if allowed_prefixes and not any(file.startswith(pref) for pref in allowed_prefixes):
                continue

            dd[(loc, pl)].append(file)

    # results = []
    # print(dd)
    for (k1, k2), v in dd.items():
        if allowed_platforms and k2 not in allowed_platforms:
            continue
        if k2 == 'FortiOS':
            # print(k ,v)
            for vv in v:
                res = FortiOSParser.from_local_file(vv, search_text[0], search_text[1],strict_mode=strict_mode)
                # print(res)
                if res:
                    yield(f"----{k2} {k1} {region(vv)}----")
                    yield(vv + ": \n" + "\n".join(res) + "\n")
        if k2 in ('Cisco ASA', 'Cisco FXOS', 'Cisco PIX'):
            # print(k ,v)
            for vv in v:
                res = CiscoASAParser3.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
                if res:
                    yield(f"----{k2} {k1} {region(vv)}----")
                    yield(vv + ": \n" + "\n".join(res) + "\n")

        if k2 in ('Cisco IOS','HP ProCurve','B4COM BCOM-OS-DC','EdgeCore','IBM_Lenovo Network OS','Dell Networking OS') :
            for vv in v:
                res = CiscoIOSParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
                if res:
                    yield(f"----{k2} {k1} {region(vv)}----")
                    yield(vv + ": \n" + "\n".join(res) + "\n")
        if k2 in ('Cisco IOS XE','Cisco IOS XR'):
            for vv in v:
                # print(vv)
                res = CiscoIOSXEParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
                # print(res)
                if res:
                    yield(f"----{k2} {k1} {region(vv)}----")
                    yield(vv + ": \n" + "\n".join(res) + "\n")
        if k2 == 'Cisco NX-OS':
            for vv in v:
                res = CiscoNexusParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
                if res:
                    yield(f"----{k2} {k1} {region(vv)}----")
                    yield(vv + ": \n" + "\n".join(res) + "\n")

        if k2 in ('Huawei VRP','Huawei VRP 2403'):
            for vv in v:
                res = HuaweiParser3.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
                if res:
                    yield(f"----{k2} {k1} {region(vv)}----")
                    yield(vv + ": \n" + "\n".join(res) + "\n")

        if k2 == 'Juniper Junos':
            for vv in v:
                res = JuniperACLParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
                if res:
                    yield (f"----{k2} {k1} {region(vv)}----")
                    yield(vv + ": \n" + "\n".join(res) + "\n")

        if k2 == 'Eltex':
            for vv in v:
                res = EltexACLParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
                if res:
                    # print(res)
                    yield (f"----{k2} {k1} {region(vv)}----")
                    yield(vv + ": \n" + "\n".join(res) + "\n")
        if k2 == 'Eltex ESR':
            # print(v)
            for vv in v:
                res = EltexESRParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
                print(res)
                if res:
                    yield (f"----{k2} {k1} {region(vv)}----")
                    yield(vv + ": \n" + "\n".join(res) + "\n")
        # if k2  == 'HP ProCurve' :
        #     for vv in v:
        #         res = CiscoIOSParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
        #         if res:
        #             yield(f"----{k2} {k1} {region(vv)}----")
        #             yield(vv + ": \n" + "\n".join(res) + "\n")
        if k2 in ('HPE OfficeConnect', 'HPE Comware 1910', 'HPE Comware','3Com Comware 1910'):
            for vv in v:  # список файлов
                res = HPEParser.from_local_file(vv, search_text[0], search_text[1], strict_mode=strict_mode)
                if res:
                    yield (f"----{k2} {k1} {region(vv)}----")
                    yield (vv + ": \n" + "\n".join(res) + "\n")

    # return results


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