import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import ipaddress
from collections import defaultdict
import re
import os



class CiscoIOSXEParser:
    def __init__(self, config_text):
        self.config_lines = config_text.splitlines()
        self.object_groups = defaultdict(list)
        self.acl_lines = []  # list of (acl_name, rule_line, seq_number, acl_type, header_prefix)
        self.parse()

    def _is_ip(self, s):
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    def _is_mask(self, s):
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    def _wildcard_to_cidr(self, wildcard):
        try:
            wildcard_int = int(ipaddress.IPv4Address(wildcard))
            subnet_mask_int = 0xFFFFFFFF ^ wildcard_int
            prefix = bin(subnet_mask_int).count('1')
            return prefix
        except Exception as e:
            # print(f"[DEBUG] _wildcard_to_cidr: Error for wildcard={wildcard}: {e}")
            return None

    def _mask_to_cidr(self, mask):
        try:
            mask_int = int(ipaddress.IPv4Address(mask))
            prefix = bin(mask_int).count('1')
            return prefix
        except:
            return None

    def _cand_to_net(self, cand):
        try:
            if isinstance(cand, str):
                if '/' in cand:
                    return ipaddress.ip_network(cand, strict=False)
                elif ' ' in cand:
                    parts = cand.split()
                    if len(parts) == 2:
                        prefix = self._wildcard_to_cidr(parts[1]) or self._mask_to_cidr(parts[1])
                        if prefix is not None:
                            return ipaddress.ip_network(f"{parts[0]}/{prefix}", strict=False)
                else:
                    return ipaddress.ip_network(cand + '/32', strict=False)
        except ValueError as e:
            # print(f"[DEBUG] _cand_to_net: Error for cand={cand}: {e}")
            return None
        return None

    def _matches(self, input_str, candidates, strict_mode):
        # print(f"[DEBUG] _matches: input_str={input_str}, candidates={candidates}, strict_mode={strict_mode}")
        if not input_str and any(c == "any" for c in candidates):
            # print(f"[DEBUG] _matches: Empty input matches 'any'")
            return True
        if input_str == "any":
            if strict_mode:
                if "any" in candidates:
                    # print(f"[DEBUG] _matches: Input 'any' matches 'any' in candidates (strict_mode=True)")
                    return True
                else:
                    # print(f"[DEBUG] _matches: Input 'any' does not match candidates (strict_mode=True)")
                    return False
            else:
                # print(f"[DEBUG] _matches: Input 'any' matches any candidate (strict_mode=False)")
                return True
        try:
            if '/' in input_str:
                input_net = ipaddress.ip_network(input_str, strict=False)
                for cand in candidates:
                    if cand == "any" and strict_mode:
                        continue
                    cand_net = self._cand_to_net(cand)
                    if cand_net and cand_net == input_net:
                        # print(f"[DEBUG] _matches: Network match: input_net={input_net}, cand_net={cand_net}")
                        return True
                # print(f"[DEBUG] _matches: No network match for input_net={input_net}")
                return False
            else:
                input_ip = ipaddress.ip_address(input_str)
                input_net_32 = ipaddress.ip_network(str(input_ip) + '/32', strict=False)
                for cand in candidates:
                    if cand == "any" and strict_mode:
                        continue
                    cand_net = self._cand_to_net(cand)
                    if cand_net:
                        if strict_mode:
                            if cand_net == input_net_32:
                                # print(f"[DEBUG] _matches: Strict IP match: input_ip={input_ip}, cand_net={cand_net}")
                                return True
                        else:
                            if input_ip in cand_net:
                                # print(f"[DEBUG] _matches: IP in network: input_ip={input_ip}, cand_net={cand_net}")
                                return True
                            # else:
                            #     print(f"[DEBUG] _matches: IP {input_ip} not in network {cand_net}")
                        continue
                    elif self._is_ip(cand):
                        if input_ip == ipaddress.ip_address(cand):
                            # print(f"[DEBUG] _matches: Exact IP match: input_ip={input_ip}, cand={cand}")
                            return True
                        # else:
                            # print(f"[DEBUG] _matches: No exact IP match: input_ip={input_ip}, cand={cand}")
                # print(f"[DEBUG] _matches: No match for input_ip={input_ip}")
                return False
        except ValueError as e:
            # print(f"[DEBUG] _matches: ValueError: {e}")
            return False

    def _extract_src_dst(self, parts, acl_type):
        i = 0
        if parts[0] == 'access-list':
            i = 2
        if i < len(parts) and parts[i].isdigit():
            i += 1
        if i < len(parts) and parts[i] in ['permit', 'deny']:
            i += 1
        if i < len(parts) and parts[i] == 'ipv4':  # Handle IOS XR
            i += 1
        if acl_type == 'extended' and i < len(parts) and parts[i] not in ['any', 'host', 'object-group'] and not self._is_ip(parts[i]):
            i += 1

        def parse_entry(idx):
            if idx >= len(parts):
                return "any", idx
            word = parts[idx]
            if word == "object-group":
                if idx + 1 < len(parts):
                    return parts[idx + 1], idx + 2
                return "any", idx + 2
            elif word == "host":
                if idx + 1 < len(parts) and self._is_ip(parts[idx + 1]):
                    return parts[idx + 1] + "/32", idx + 2
                return "any", idx + 2
            elif word == "any":
                return "any", idx + 1
            elif self._is_ip(word):
                if idx + 1 < len(parts) and self._is_mask(parts[idx + 1]):
                    prefix = self._wildcard_to_cidr(parts[idx + 1]) or self._mask_to_cidr(parts[idx + 1])
                    if prefix is not None:
                        return f"{parts[idx]}/{prefix}", idx + 2
                    else:
                        return parts[idx] + "/32", idx + 1
                else:
                    return parts[idx] + "/32", idx + 1
            return "any", idx + 1

        src, i = parse_entry(i)
        if acl_type == 'standard':
            return src, "any"

        while i < len(parts) and parts[i] in ['eq', 'range', 'gt', 'lt', 'established', 'log']:
            i += 2 if parts[i] in ['eq', 'gt', 'lt', 'log', 'established'] else 3

        dst, i = parse_entry(i)
        while i < len(parts) and parts[i] in ['eq', 'range', 'gt', 'lt', 'established', 'log']:
            i += 2 if parts[i] in ['eq', 'gt', 'lt', 'log', 'established'] else 3

        return src, dst

    def _resolve_entry(self, entry):
        if not entry or entry == "any":
            return ["any"]
        if "/" in entry or self._is_ip(entry):
            return [entry]
        if entry in self.object_groups:
            resolved = []
            for sub in self.object_groups[entry]:
                if self._is_ip(sub) and '/' not in sub:
                    resolved.append(sub + "/32")
                else:
                    resolved.extend(self._resolve_entry(sub))
            return resolved
        return []

    def parse(self):
        current_group = None
        current_values = []
        current_acl = None
        acl_type = ''
        in_acl = False

        for line_num, line in enumerate(self.config_lines):
            original_line = line.strip()
            line = line.strip()
            if not line:
                continue

            # print(f"[DEBUG] Processing line {line_num}: '{line}'")

            # Object groups
            if line.startswith("object-group network "):
                if current_group:
                    self.object_groups[current_group] = current_values
                    # print(f"[DEBUG] Closing object-group: {current_group}")
                current_group = line.split()[2]
                current_values = []
                # print(f"[DEBUG] Starting object-group: {current_group}")
                continue

            if current_group:
                if line == "exit" or line.endswith("}"):
                    self.object_groups[current_group] = current_values
                    # print(f"[DEBUG] Ending object-group: {current_group} with {len(current_values)} entries")
                    current_group = None
                    current_values = []
                    continue

                if (line.startswith("access-list ") or
                        line.startswith("ip access-list ") or
                        line.startswith("ipv4 access-list ") or
                        line.startswith("route-map ") or
                        line.startswith("ip prefix-list ") or
                        line.startswith("crypto ") or
                        line.startswith("aaa ") or
                        line.startswith("snmp-server ") or
                        line.startswith("logging ") or
                        line.startswith("ntp ")):
                    self.object_groups[current_group] = current_values
                    # print(f"[DEBUG] Closing object-group due to new section: {current_group}")
                    current_group = None
                    current_values = []

                if current_group:
                    parts = line.split()
                    if not parts:
                        continue
                    if parts[0].isdigit():
                        parts = parts[1:]
                    if not parts:
                        continue
                    word = parts[0]
                    if word == "description":
                        continue
                    elif word == "host":
                        if len(parts) > 1 and self._is_ip(parts[1]):
                            current_values.append(parts[1] + "/32")
                            # print(f"[DEBUG] Added host to {current_group}: {parts[1]}/32")
                    elif word == "group-object":
                        if len(parts) > 1:
                            current_values.append(parts[1])
                            # print(f"[DEBUG] Added group-object to {current_group}: {parts[1]}")
                    elif len(parts) == 2 and self._is_ip(parts[0]) and self._is_mask(parts[1]):
                        try:
                            prefix = self._mask_to_cidr(parts[1]) or self._wildcard_to_cidr(parts[1])
                            if prefix is not None:
                                network = ipaddress.ip_network(f"{parts[0]}/{prefix}", strict=False)
                                current_values.append(str(network))
                                # print(f"[DEBUG] Added network to {current_group}: {network}")
                        except ValueError as e:
                            # print(f"[DEBUG] parse: Error processing network {parts[0]} {parts[1]}: {e}")
                            continue
                    elif self._is_ip(word):
                        current_values.append(word + "/32")
                        # print(f"[DEBUG] Added IP to {current_group}: {word}/32")
                    continue

            # Numbered ACLs
            if line.startswith("access-list "):
                parts = line.split(maxsplit=3)
                if len(parts) > 2:
                    acl_name = parts[1]
                    rule = ' '.join(parts[2:])
                    seq_number = parts[2] if len(parts) > 2 and parts[2].isdigit() else None
                    try:
                        acl_num = int(acl_name)
                        acl_type = 'standard' if 1 <= acl_num <= 99 or 1300 <= acl_num <= 1999 else 'extended'
                    except ValueError:
                        acl_type = 'standard'
                    # print(f"[DEBUG] Parsing numbered ACL: acl_name={acl_name}, rule={rule}, seq={seq_number}, type={acl_type}")
                    self.acl_lines.append((acl_name, rule, seq_number, acl_type, 'access-list'))
                continue

            # Named ACLs (IOS, IOS XE, IOS XR)
            if line.startswith("ip access-list ") or line.startswith("ipv4 access-list "):
                # print(f"[DEBUG] Found ACL header: '{line}'")
                parts = line.split(maxsplit=4)
                header_prefix = 'ip access-list' if line.startswith("ip access-list ") else 'ipv4 access-list'
                if len(parts) >= 3:
                    acl_type = parts[2] if len(parts) == 4 and parts[2] in ['standard', 'extended'] else 'extended'
                    current_acl = parts[3] if len(parts) == 4 else parts[2]
                    in_acl = True
                    # print(f"[DEBUG] Starting ACL: {header_prefix} {acl_type} {current_acl}")
                continue

            # Rules
            if in_acl:
                if line == "exit" or line.endswith("}"):
                    # print(f"[DEBUG] Ending ACL: {current_acl}")
                    in_acl = False
                    current_acl = None
                    acl_type = ''
                    continue

                parts = line.split()
                seq_number = None
                if parts and parts[0].isdigit():
                    seq_number = parts[0]
                    parts = parts[1:]

                rule = ' '.join(parts)
                if rule.startswith("permit") or rule.startswith("deny"):
                    # print(f"[DEBUG] Adding ACL rule: {current_acl} - {rule}")
                    self.acl_lines.append((current_acl, rule, seq_number, acl_type, header_prefix))
                continue

        if current_group:
            self.object_groups[current_group] = current_values
            # print(f"[DEBUG] Closing object-group at EOF: {current_group}")

        # print(f"[DEBUG] Total ACL lines parsed: {len(self.acl_lines)}")
        # print(f"[DEBUG] Total object-groups parsed: {len(self.object_groups)}")

    def find_acl_matches(self, src_ip, dst_ip, strict_mode=False):
        matches = []
        current_acl = None
        for acl_name, full_line, seq_number, acl_type, header_prefix in self.acl_lines:
            parts = full_line.split()
            # print(f"[DEBUG] Processing ACL: acl_name={acl_name}, line={full_line}, seq={seq_number}, acl_type={acl_type}, header_prefix={header_prefix}")
            try:
                src_entry, dst_entry = self._extract_src_dst(parts, acl_type)
                src_ips = self._resolve_entry(src_entry)
                dst_ips = self._resolve_entry(dst_entry)
                # print(f"[DEBUG] Extracted: src_entry={src_entry}, dst_entry={dst_entry}, src_ips={src_ips}, dst_ips={dst_ips}")

                is_special_case = (not src_ip or src_ip == "any") and (not dst_ip or dst_ip == "any")
                if is_special_case:
                    # print(f"[DEBUG] Matched: acl={acl_name}, line={full_line}, special case inputs")
                    if acl_name != current_acl:
                        if header_prefix == 'access-list' and acl_name.isdigit():
                            header = f"access-list {acl_name}"
                        elif header_prefix == 'ipv4 access-list':
                            header = f"ipv4 access-list {acl_name}"
                        else:
                            header = f"{header_prefix} {acl_type} {acl_name}"
                        matches.append(header)
                        current_acl = acl_name
                    matches.append(f" {full_line}")
                else:
                    src_ok = self._matches(src_ip, src_ips, strict_mode)
                    dst_ok = self._matches(dst_ip, dst_ips, strict_mode)
                    if src_ok and dst_ok:
                        # print(f"[DEBUG] Matched: acl={acl_name}, line={full_line}, src_ok={src_ok}, dst_ok={dst_ok}")
                        if acl_name != current_acl:
                            if header_prefix == 'access-list' and acl_name.isdigit():
                                header = f"access-list {acl_name}"
                            elif header_prefix == 'ipv4 access-list':
                                header = f"ipv4 access-list {acl_name}"
                            else:
                                header = f"{header_prefix} {acl_type} {acl_name}"
                            matches.append(header)
                            current_acl = acl_name
                        matches.append(f" {full_line}")
            except Exception as e:
                print(f"[!] Error: {e} in line: {full_line}")
                continue
        return tuple(matches)

    @classmethod
    def from_local_file(cls, filename, src_ip, dst_ip, strict_mode=False, base_dir="collected_files_clear", encoding="utf-8"):
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file == filename:
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "r", encoding=encoding, errors="ignore") as f:
                            config_text = f.read()
                        # print(f"[DEBUG] Found and reading file: {full_path}")
                    except Exception as e:
                        print(f"[!] Error reading {full_path}: {e}")
                        continue
                    parser = cls(config_text)
                    return parser.find_acl_matches(src_ip, dst_ip, strict_mode)
        print(f"⚠️ File {filename} not found in directory {base_dir}")
        return tuple()
class CiscoIOSParser:
    def __init__(self, config_text, hp_procurve=False):
        self.config_lines = config_text.splitlines()
        self.object_groups = defaultdict(list)
        self.acls = {}  # {acl_name: {'type': 'standard'|'extended', 'rules': [raw_line, ...], 'header_prefix': 'ip'|'access-list ip'}}
        self.hp_procurve = hp_procurve
        self.parse()

    def _wildcard_to_cidr(self, wildcard):
        try:
            mask = int(ipaddress.IPv4Address(wildcard))
            prefix = 32 - bin(mask).count('1')
            return prefix
        except:
            return None

    def _mask_to_cidr(self, mask):
        try:
            mask_int = int(ipaddress.IPv4Address(mask))
            prefix = bin(mask_int).count('1')
            return prefix
        except:
            return None

    def _expand_ip_range(self, start_ip, end_ip):
        try:
            start = ipaddress.IPv4Address(start_ip)
            end = ipaddress.IPv4Address(end_ip)
            return [(start, end)]
        except ValueError:
            return []

    def _cand_to_net(self, cand):
        try:
            if isinstance(cand, str):
                if '/' in cand:
                    return ipaddress.ip_network(cand, strict=False)
                elif ' ' in cand:
                    parts = cand.split()
                    if len(parts) == 2:
                        prefix = self._wildcard_to_cidr(parts[1]) or self._mask_to_cidr(parts[1])
                        if prefix is not None:
                            return ipaddress.ip_network(f"{parts[0]}/{prefix}", strict=False)
                else:
                    return ipaddress.ip_network(cand + '/32', strict=False)
            elif isinstance(cand, tuple):
                if len(cand) == 2 and cand[0] == cand[1]:
                    return ipaddress.ip_network(str(cand[0]) + '/32', strict=False)
        except ValueError:
            return None
        return None

    def _is_ip(self, s):
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    def _matches(self, input_str, candidates, strict_mode, is_standard_acl=False):
        if input_str == "any":
            return True
        if "any" in candidates:
            return not strict_mode or is_standard_acl  # For standard ACL, dst=any always matches in strict mode if input is any
        try:
            if '/' in input_str:  # Network input
                input_net = ipaddress.ip_network(input_str, strict=False)
                for candid in candidates:
                    cand_net = self._cand_to_net(candid)
                    if cand_net and cand_net == input_net:
                        return True
                return False
            else:  # IP input
                input_ip = ipaddress.ip_address(input_str)
                input_net_32 = ipaddress.ip_network(str(input_ip) + '/32', strict=False)
                for candid in candidates:
                    if strict_mode:
                        cand_net = self._cand_to_net(candid)
                        if cand_net and cand_net == input_net_32:
                            return True
                    else:
                        try:
                            if isinstance(candid, tuple) and len(candid) == 2:
                                start, end = candid
                                if start <= input_ip <= end:
                                    return True
                            elif "/" in candid or ' ' in candid:
                                cand_net = self._cand_to_net(candid)
                                if cand_net and input_ip in cand_net:
                                    return True
                            elif self._is_ip(candid):
                                if input_ip == ipaddress.ip_address(candid):
                                    return True
                            else:
                                parts = candid.split('/')
                                if len(parts) == 2 and self._is_ip(parts[0]):
                                    if input_ip == ipaddress.ip_address(parts[0]):
                                        return True
                        except Exception:
                            continue
                return False
        except ValueError:
            return False

    def parse(self):
        self._parse_object_groups()
        current_group = None
        current_acl = None
        current_type = 'extended'  # Default
        for line in self.config_lines:
            line = line.strip()
            if not line:
                continue

            # IBM Lenovo: access management-network
            if line.startswith("access management-network"):
                parts = line.split()
                if len(parts) >= 3 and self._is_ip(parts[2]):
                    acl_name = "management-network"
                    if acl_name not in self.acls:
                        self.acls[acl_name] = {'type': 'standard', 'rules': [], 'header_prefix': 'access'}
                    rule = f"permit {parts[2]} {parts[3]}"
                    self.acls[acl_name]['rules'].append(rule)
                continue

            # EdgeCore/Cisco numbered ACLs
            if line.startswith("access-list ip ") or line.startswith("access-list "):
                parts = line.split(maxsplit=3)
                if len(parts) >= 3 and parts[1] == "ip" and parts[2] in ("standard", "extended"):
                    acl_type = parts[2]
                    acl_name = parts[3].strip('"')  # Strip quotes for HP ProCurve compatibility
                    if acl_name not in self.acls:
                        self.acls[acl_name] = {'type': acl_type, 'rules': [], 'header_prefix': 'access-list ip'}
                    current_acl = acl_name
                    current_type = acl_type
                    continue
                elif len(parts) > 2:
                    acl_name = parts[1]
                    if acl_name.isdigit():
                        acl_type = 'standard' if int(acl_name) < 100 or 1300 <= int(acl_name) <= 1999 else 'extended'
                        rule = ' '.join(parts[2:])
                        if acl_name not in self.acls:
                            self.acls[acl_name] = {'type': acl_type, 'rules': [], 'header_prefix': 'access-list'}
                        self.acls[acl_name]['rules'].append(rule)
                    continue

            # Named ACLs (Cisco, Ip Infusion, Dell, HP ProCurve)
            if line.startswith("ip access-list "):
                parts = line.split(maxsplit=4)
                acl_type = 'extended'  # Default
                acl_name = None
                if len(parts) >= 4 and parts[2] in ("standard", "extended"):
                    acl_type = parts[2]
                    acl_name = parts[3].strip('"')
                elif len(parts) >= 3:
                    acl_name = parts[2].strip('"')
                if acl_name and acl_name not in self.acls:
                    self.acls[acl_name] = {'type': acl_type, 'rules': [], 'header_prefix': 'ip access-list'}
                current_acl = acl_name
                current_type = acl_type
                continue

            # Object groups
            if line.startswith("object-group network "):
                if current_group:
                    self.object_groups[current_group] = current_values
                current_group = line.split()[2]
                current_values = []
                continue

            if current_group:
                if line.startswith("host "):
                    current_values.append(line.split()[1] + "/32")
                elif line.startswith("range "):
                    parts = line.split()
                    current_values.extend(self._expand_ip_range(parts[1], parts[2]))
                elif re.match(r"\d", line):
                    parts = line.split()
                    if len(parts) == 2:
                        try:
                            network = ipaddress.ip_network(f"{parts[0]}/{self._wildcard_to_cidr(parts[1])}", strict=False)
                            current_values.append(str(network))
                        except ValueError:
                            continue
                elif line == "exit" or line.endswith("}"):
                    self.object_groups[current_group] = current_values
                    current_group = None
                continue

            # Rules
            if current_acl:
                if line.startswith("permit") or line.startswith("deny") or line[0].isdigit() or line.startswith("seq "):
                    self.acls[current_acl]['rules'].append(line)
                elif line == "exit" or line.endswith("}"):
                    current_acl = None

    def _parse_object_groups(self):
        current_name = None
        current_values = []
        for line in self.config_lines:
            s = line.strip()
            if s.startswith("object-group ip address") or s.startswith("object-group network"):
                if current_name:
                    self.object_groups[current_name] = current_values
                current_name = s.split()[-1]
                current_values = []
            elif current_name:
                if s.startswith("host-info "):
                    ip = s.split()[-1]
                    current_values.append(ip + "/32")
                elif s.startswith("host "):
                    ip = s.split()[-1]
                    current_values.append(ip + "/32")
                elif re.match(r"\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+", s):
                    ip, mask = s.split()[:2]
                    prefix = self._mask_to_cidr(mask)
                    if prefix is not None:
                        current_values.append(f"{ip}/{prefix}")
                elif s.startswith("exit") or s == "!":
                    self.object_groups[current_name] = current_values
                    current_name = None
                    current_values = []
        if current_name:
            self.object_groups[current_name] = current_values

    def _extract_src_dst(self, parts, acl_type):
        i = 0
        # Skip sequence number or "seq <num>"
        if parts and (parts[i].isdigit() or parts[i] == "seq"):
            i += 1
            if parts[i-1] == "seq" and i < len(parts):
                i += 1
        # Skip action
        if i < len(parts) and parts[i] in ['permit', 'deny']:
            i += 1

        # For extended, skip protocol
        if acl_type == 'extended':
            if i < len(parts) and parts[i] not in ['any', 'host', 'object-group', 'addrgroup', 'range'] and not re.match(r'\d+\.\d+\.\d+\.\d+(?:/\d+)?', parts[i]):
                i += 1

        def parse_entry(idx):
            if idx >= len(parts):
                return "any", idx
            word = parts[idx]
            if word in ["object-group", "addrgroup"]:
                return parts[idx + 1], idx + 2
            elif word == "host":
                return parts[idx + 1] + "/32", idx + 2
            elif word == "any":
                return "any", idx + 1
            elif re.match(r'\d+\.\d+\.\d+\.\d+/\d+', word):  # CIDR
                return word, idx + 1
            elif self._is_ip(word):
                if idx + 1 < len(parts) and (self._is_ip(parts[idx + 1]) or re.match(r'\d+\.\d+\.\d+\.\d+', parts[idx + 1])):
                    mask = parts[idx + 1]
                    if re.match(r'0\.', mask):  # Wildcard
                        prefix = self._wildcard_to_cidr(mask)
                    else:  # Subnet mask
                        prefix = self._mask_to_cidr(mask)
                    if prefix is not None:
                        return f"{parts[idx]}/{prefix}", idx + 2
                    else:
                        return parts[idx] + "/32", idx + 1
                else:
                    return parts[idx] + "/32", idx + 1
            return "any", idx + 1

        src, i = parse_entry(i)

        # For standard ACLs, destination is always 'any'
        dst = "any" if acl_type == 'standard' else parse_entry(i)[0]

        # For extended ACLs, parse destination and skip extras
        if acl_type == 'extended':
            dst, i = parse_entry(i)
            # Skip destination ports or extras
            while i < len(parts) and parts[i] in ["eq", "gt", "lt", "neq", "range", "established", "destination-port", "log", "threshold-in-msgs", "interval"]:
                i += 1
                if i < len(parts):
                    i += 1
                    if parts[i-2] in ["range", "threshold-in-msgs", "interval"] and i < len(parts):
                        i += 1

        return src, dst

    def _resolve_entry(self, entry):
        if not entry or entry == "any":
            return ["any"]
        if "/" in entry or self._is_ip(entry) or ' ' in entry:
            return [entry]
        if entry in self.object_groups:
            return self.object_groups[entry]
        return []

    def find_acl_matches(self, src_ip, dst_ip, strict_mode=False):
        matches = []
        for acl_name, acl_data in self.acls.items():
            acl_type = acl_data['type']
            acl_rules = []
            for rule in acl_data['rules']:
                if rule.startswith('remark') or not rule.strip():
                    continue
                parts = rule.split()
                if not parts:
                    continue
                try:
                    src_entry, dst_entry = self._extract_src_dst(parts, acl_type)
                    src_ips = self._resolve_entry(src_entry)
                    dst_ips = self._resolve_entry(dst_entry)

                    # Skip rules with src=any and dst=any
                    if src_ips == ["any"] and dst_ips == ["any"]:
                        continue

                    src_ok = self._matches(src_ip, src_ips, strict_mode, is_standard_acl=(acl_type == 'standard'))
                    # For standard ACL, dst_ok is True only if dst_ip is "any" in strict_mode
                    dst_ok = (acl_type == 'standard' and (not strict_mode or dst_ip == "any")) or \
                             self._matches(dst_ip, dst_ips, strict_mode, is_standard_acl=False)
                    if src_ok and dst_ok:
                        acl_rules.append(rule)
                except Exception:
                    continue
            if acl_rules:
                header = f"access-list {acl_name}" if acl_name.isdigit() else f"ip access-list {acl_type} {acl_name}"
                matches.append(header)
                for rule in acl_rules:
                    matches.append(f" {rule}")
        return tuple(matches)

    @classmethod
    def from_local_file(cls, filename, src_ip, dst_ip, strict_mode=False, base_dir="collected_files_clear",
                        encoding="utf-8"):
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file == filename:
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "r", encoding=encoding, errors="ignore") as f:
                            config_text = f.read()
                    except Exception as e:
                        print(f"[!] Error reading {full_path}: {e}")
                        continue
                    parser = cls(config_text)
                    return parser.find_acl_matches(src_ip, dst_ip, strict_mode)
        print(f"⚠️ File {filename} not found in directory {base_dir}")
        return tuple()
class CiscoASAParser3:
        def __init__(self, config_text):
            self.config_lines = config_text.splitlines()
            self.objects = {}  # object network name -> [networks]
            self.object_groups = defaultdict(list)  # object-group network -> [networks/objects]
            self.acl_lines = []  # access-list строки
            self.parse()

        @classmethod
        def from_local_file(cls, filename, src_ip, dst_ip, strict_mode=False, base_dir="collected_files_clear",
                            encoding="utf-8"):
            for root, _, files in os.walk(base_dir):
                for file in files:
                    if file == filename:
                        full_path = os.path.join(root, file)
                        try:
                            with open(full_path, "r", encoding=encoding, errors="ignore") as f:
                                config_text = f.read()
                        except Exception as e:
                            print(f"[!] Error reading {full_path}: {e}")
                            continue
                        parser = cls(config_text)
                        return parser.find_acl_matches(src_ip, dst_ip, strict_mode)
            print(f"⚠️ File {filename} not found in directory {base_dir}")
            return tuple()

        def parse(self):
            self._parse_objects()
            self._parse_object_groups()
            self._parse_acls()

        def _parse_objects(self):
            current_name = None
            current_values = []

            for line in self.config_lines:
                line = line.strip()
                if line.startswith("object network "):
                    if current_name:
                        self.objects[current_name] = current_values
                    current_name = line.split("object network ")[1]
                    current_values = []
                elif line.startswith("host "):
                    ip = line.split()[1]
                    current_values.append(ip + "/32")
                elif line.startswith("range "):
                    parts = line.split()
                    current_values.extend(self._expand_ip_range(parts[1], parts[2]))
                elif line.startswith("subnet "):
                    parts = line.split()
                    try:
                        network = ipaddress.ip_network((parts[1], parts[2]), strict=False)
                        current_values.append(str(network))
                    except ValueError:
                        continue
            if current_name:
                self.objects[current_name] = current_values

        def _parse_object_groups(self):
            current_group = None
            current_values = []

            for line in self.config_lines:
                line = line.strip()
                if line.startswith("object-group network "):
                    if current_group:
                        self.object_groups[current_group] = current_values
                    current_group = line.split("object-group network ")[1]
                    current_values = []
                elif line.startswith("network-object host "):
                    ip = line.split()[-1]
                    current_values.append(ip + "/32")
                elif line.startswith("network-object object "):
                    obj = line.split()[-1]
                    current_values.extend(self.objects.get(obj, []))
                elif line.startswith("network-object "):
                    parts = line.split()
                    if len(parts) == 3:
                        try:
                            network = ipaddress.ip_network((parts[1], parts[2]), strict=False)
                            current_values.append(str(network))
                        except ValueError:
                            continue
                elif line.startswith("group-object "):
                    ref = line.split()[-1]
                    current_values.append(("group", ref))
            if current_group:
                self.object_groups[current_group] = current_values

            # Разворачиваем вложенные группы
            for group, values in list(self.object_groups.items()):
                expanded = []
                for val in values:
                    if isinstance(val, tuple) and val[0] == "group":
                        expanded.extend(self._resolve_group(val[1]))
                    else:
                        expanded.append(val)
                self.object_groups[group] = expanded

        def _parse_acls(self):
            for line in self.config_lines:
                line = line.strip()
                if line.startswith("access-list ") and not ("remark" in line or "description" in line):
                    self.acl_lines.append(line)

        def _expand_ip_range(self, start_ip, end_ip):
            try:
                start = ipaddress.IPv4Address(start_ip)
                end = ipaddress.IPv4Address(end_ip)
                return [(start, end)]  # диапазон
            except ValueError:
                return []

        def _resolve_group(self, name):
            results = []
            visited = set()

            def _resolve(n):
                if n in visited:
                    return
                visited.add(n)
                if n in self.object_groups:
                    for val in self.object_groups[n]:
                        if isinstance(val, tuple) and val[0] == "group":
                            _resolve(val[1])
                        else:
                            results.append(val)
                elif n in self.objects:
                    results.extend(self.objects[n])

            _resolve(name)
            return results

        def _resolve_entry(self, entry):
            if not entry or entry == "any" or entry == "any4":
                return ["any"]
            if isinstance(entry, tuple):  # диапазон или netmask
                return [entry]
            if "/" in entry or self._is_ip(entry):
                return [entry]
            if entry in self.objects:
                return self.objects[entry]
            if entry in self.object_groups:
                return self.object_groups[entry]
            return []

        def _is_ip(self, s):
            try:
                ipaddress.ip_address(s)
                return True
            except ValueError:
                return False

        def _is_dotted_decimal(self, s):
            parts = s.split('.')
            if len(parts) != 4:
                return False
            for p in parts:
                if not p.isdigit() or not 0 <= int(p) <= 255:
                    return False
            return True

        def _cand_to_net(self, cand):
            try:
                if isinstance(cand, str):
                    if '/' in cand:
                        return ipaddress.ip_network(cand, strict=False)
                    elif ' ' in cand:
                        parts = cand.split()
                        if len(parts) == 2:
                            return ipaddress.ip_network((parts[0], parts[1]), strict=False)
                    else:
                        return ipaddress.ip_network(cand + '/32', strict=False)
                elif isinstance(cand, tuple):
                    if len(cand) == 3 and cand[0] == 'netmask':
                        return ipaddress.ip_network((cand[1], cand[2]), strict=False)
                    elif len(cand) == 2:
                        if cand[0] == cand[1]:
                            return ipaddress.ip_network(str(cand[0]) + '/32', strict=False)
                        else:
                            return None
            except ValueError:
                return None
            return None

        def _matches(self, input_str, candidates, strict_mode):
            if input_str == "any":
                return True

            try:
                if '/' in input_str:  # network
                    input_net = ipaddress.ip_network(input_str, strict=False)
                    for cand in candidates:
                        cand_net = self._cand_to_net(cand)
                        if cand_net and cand_net == input_net:
                            return True
                    return False
                else:  # IP
                    input_ip = ipaddress.ip_address(input_str)
                    input_net_32 = ipaddress.ip_network(str(input_ip) + '/32', strict=False)
                    for cand in candidates:
                        if strict_mode:
                            # only exact /32
                            cand_net = self._cand_to_net(cand)
                            if cand_net and cand_net == input_net_32:
                                return True
                        else:
                            try:
                                if isinstance(cand, tuple):
                                    if len(cand) == 3 and cand[0] == 'netmask':
                                        net = ipaddress.ip_network((cand[1], cand[2]), strict=False)
                                        if input_ip in net:
                                            return True
                                    elif len(cand) == 2:
                                        start, end = cand
                                        if start <= input_ip <= end:
                                            return True
                                elif cand.startswith("host "):
                                    cand_ip = cand.split()[1]
                                    if input_ip == ipaddress.ip_address(cand_ip):
                                        return True
                                elif "/" in cand:  # CIDR
                                    if input_ip in ipaddress.ip_network(cand, strict=False):
                                        return True
                                else:
                                    parts = cand.split()
                                    if len(parts) == 2:  # ip + mask
                                        net_ip, mask = parts
                                        net = ipaddress.ip_network((net_ip, mask), strict=False)
                                        if input_ip in net:
                                            return True
                                    elif self._is_ip(cand):
                                        if input_ip == ipaddress.ip_address(cand):
                                            return True
                            except Exception:
                                continue
                    return False
            except ValueError:
                return False

        def _extract_src_dst(self, parts):
            i = 4
            if parts[i] in ['ip', 'tcp', 'udp', 'icmp']:
                i += 1
            elif i < len(parts) and parts[i] == 'object-group':
                i += 2

            def parse_entry(idx):
                if idx >= len(parts):
                    return None, idx + 1
                if parts[idx] in ("object-group", "object"):
                    return parts[idx + 1], idx + 2
                elif parts[idx] == "host":
                    return parts[idx + 1] + "/32", idx + 2
                elif parts[idx] == "any" or parts[idx] == "any4":
                    return "any", idx + 1
                elif self._is_ip(parts[idx]):
                    if idx + 1 < len(parts) and self._is_dotted_decimal(parts[idx + 1]):
                        second = parts[idx + 1]
                        if second.startswith('255'):
                            # Treat as netmask
                            return ('netmask', parts[idx], second), idx + 2
                        else:
                            # Treat as range (though rare in ACLs)
                            try:
                                start = ipaddress.ip_address(parts[idx])
                                end = ipaddress.ip_address(second)
                                if start > end:
                                    start, end = end, start
                                return (start, end), idx + 2
                            except ValueError:
                                return parts[idx] + "/32", idx + 1
                    else:
                        return parts[idx] + "/32", idx + 1
                return None, idx + 1

            src, i = parse_entry(i)
            dst, i = parse_entry(i)
            return src, dst

        def find_acl_matches(self, src_ip, dst_ip, strict_mode=False):
            matches = set()
            for line in self.acl_lines:
                parts = line.split()
                if len(parts) < 7:
                    continue
                try:
                    src_entry, dst_entry = self._extract_src_dst(parts)
                    src_ips = self._resolve_entry(src_entry)
                    dst_ips = self._resolve_entry(dst_entry)

                    if src_ips == ["any"] and dst_ips == ["any"]:
                        continue
                    src_ok = self._matches(src_ip, src_ips, strict_mode)
                    dst_ok = self._matches(dst_ip, dst_ips, strict_mode)

                    if src_ok and dst_ok:
                        matches.add(line)
                except Exception as e:
                    print(f"[!] Ошибка: {e} в строке: {line}")
                    continue
            return matches
class FortiOSParser:
    def __init__(self, config_text):
        self.config_text = config_text
        self.objects = {}       # {name: [ip_network or (start_ip, end_ip)]}
        self.groups = defaultdict(list)  # {group_name: [members]}
        self.policies = []      # list of policies
        self._parse_objects()
        self._parse_groups()
        self._parse_policies()

    def _parse_objects(self):
        # Parse blocks in config firewall address
        address_blocks = re.findall(r'edit "([^"]+)"(.*?)\n\s*next', self.config_text, re.S)
        for name, body in address_blocks:
            nets = []
            # Subnet
            m_subnet = re.search(r'set subnet (\S+) (\S+)', body)
            if m_subnet:
                ip, mask = m_subnet.groups()
                try:
                    prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
                    nets.append(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
                except ValueError:
                    pass
            # Range
            m_range = re.search(r'set start-ip (\S+)\s+set end-ip (\S+)', body)
            if m_range:
                start_ip, end_ip = m_range.groups()
                try:
                    nets.append((ipaddress.ip_address(start_ip), ipaddress.ip_address(end_ip)))
                except ValueError:
                    pass
            if nets:
                self.objects[name] = nets

    def _parse_groups(self):
        # Parse blocks in config firewall addrgrp
        group_blocks = re.findall(r'edit "([^"]+)"(.*?)\n\s*next', self.config_text, re.S)
        for group_name, body in group_blocks:
            if "set member" in body:
                members = re.findall(r'"([^"]+)"', body)
                self.groups[group_name].extend(m for m in members if m != group_name)

    def _resolve_group(self, name):
        results = []
        visited = set()
        def _resolve(n):
            if n in visited:
                return
            visited.add(n)
            if n in self.objects:
                results.extend(self.objects[n])
            elif n in self.groups:
                for m in self.groups[n]:
                    _resolve(m)
        _resolve(name)
        return results

    def _parse_policies(self):
        # Parse blocks in config firewall policy
        policy_blocks = re.findall(r'edit \d+(.*?)\n\s*next', self.config_text, re.S)
        for body in policy_blocks:
            if re.search(r'set status disable', body):
                continue
            src_list = re.findall(r'set srcaddr (.+)', body)
            dst_list = re.findall(r'set dstaddr (.+)', body)
            service_list = re.findall(r'set service (.+)', body)

            if src_list:
                src_list = re.findall(r'"([^"]+)"', src_list[0])
            else:
                src_list = []
            if dst_list:
                dst_list = re.findall(r'"([^"]+)"', dst_list[0])
            else:
                dst_list = []
            if service_list:
                service_list = re.findall(r'"([^"]+)"', service_list[0])
            else:
                service_list = []

            self.policies.append({
                'srcaddr': src_list,
                'dstaddr': dst_list,
                'service': service_list
            })

    def _ip_in_object(self, ip_str, obj_name, strict_mode):
        try:
            input_ip = ipaddress.ip_address(ip_str)
            input_net = ipaddress.ip_network(f"{ip_str}/32", strict=False)
            is_network_input = False
        except ValueError:
            try:
                input_net = ipaddress.ip_network(ip_str, strict=False)
                input_ip = None  # Treat as network input
                is_network_input = True
            except ValueError:
                return False

        if obj_name == "any":
            return True

        def check_object(entry):
            """Check single object entry (network or range)"""
            if isinstance(entry, tuple):
                # Range handling
                start_ip, end_ip = entry
                if input_ip is not None:  # Input is IP
                    if strict_mode:
                        return start_ip == input_ip and end_ip == input_ip
                    else:
                        return start_ip <= input_ip <= end_ip
                return False  # Ranges don't match networks
            else:
                # Network handling
                if input_ip is not None:  # Input is IP
                    if strict_mode:
                        # Strict: IP must exactly match network (only for /32)
                        return str(entry) == f"{input_ip}/32"
                    else:
                        # Non-strict: IP inside network
                        return input_ip in entry
                else:  # Input is network
                    # Networks ALWAYS match strictly (exact network match)
                    return entry == input_net

        if obj_name in self.objects:
            for entry in self.objects[obj_name]:
                if check_object(entry):
                    return True
        elif obj_name in self.groups:
            for entry in self._resolve_group(obj_name):
                if check_object(entry):
                    return True
        return False

    def search(self, src_ip, dst_ip, strict_mode=False):
        matches = set()
        for policy in self.policies:
            for src in policy['srcaddr']:
                for dst in policy['dstaddr']:
                    src_ok = True if src_ip == "any" else self._ip_in_object(src_ip, src, strict_mode)
                    dst_ok = True if dst_ip == "any" else self._ip_in_object(dst_ip, dst, strict_mode)
                    if src_ok and dst_ok:
                        matches.add(f"{src} > {dst} : {', '.join(policy['service'])}")
        return tuple(matches)  # ✅ Возвращаем tuple() вместо set()

    @classmethod
    def from_local_file(cls, filename, src_ip, dst_ip, strict_mode=False, base_dir="collected_files_clear", encoding="utf-8"):
        """
        Searches for a file in base_dir, parses it, and returns ACL matches.
        """
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file == filename:
                    full_path = os.path.join(root, filename)
                    try:
                        with open(full_path, "r", encoding=encoding, errors="ignore") as f:
                            config_text = f.read()
                    except Exception as e:
                        raise Exception(f"Error reading {full_path}: {e}")

                    parser = cls(config_text)
                    return parser.search(src_ip, dst_ip, strict_mode)

        print(f"⚠️ File {filename} not found in directory {base_dir}")
        return tuple()  # ✅ Возвращаем tuple() вместо list()
class HuaweiParser:
    def __init__(self, config_text):
        self.config_lines = config_text.splitlines()
        self.acls = {}
        self.acl_headers = {}
        self.parse()

    @classmethod
    def from_local_file(cls, filename, src_ip, dst_ip, base_dir="collected_files_clear", encoding="utf-8",
                        strict_mode=False):
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file == filename:
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "r", encoding=encoding, errors="ignore") as f:
                            config_text = f.read()
                    except Exception as e:
                        print(f"[!] Ошибка при чтении {full_path}: {e}")
                        return ()
                    parser = cls(config_text)
                    return parser.find_acl_matches(src_ip, dst_ip, strict_mode)
        print(f"⚠️ Файл {filename} не найден в директории {base_dir}")
        return ()

    def parse(self):
        current_acl = None
        current_header = None
        for raw in self.config_lines:
            line = raw.strip()
            if not line:
                continue

            if line.startswith("acl number"):
                parts = line.split()
                if len(parts) >= 3:
                    current_acl = parts[2]
                    current_header = "acl number " + current_acl
                    self.acls.setdefault(current_acl, {})
                    self.acl_headers[current_acl] = current_header
                continue
            if line.startswith("acl name"):
                parts = line.split()
                if len(parts) >= 3:
                    name = parts[2]
                    number = parts[3] if len(parts) > 3 else ""
                    current_acl = number if number else name
                    current_header = line
                    self.acls.setdefault(current_acl, {})
                    self.acl_headers[current_acl] = current_header
                continue

            if current_acl and line.startswith("rule"):
                if "description" in line.lower():
                    continue
                try:
                    pairs = self._parse_rule(line)
                    if not pairs:
                        continue
                    cleaned = []
                    for src, dst in pairs:
                        if src == "any" and dst == "any":
                            continue
                        cleaned.append((src, dst))
                    if cleaned:
                        self.acls[current_acl][line] = cleaned
                except Exception as e:
                    print(f"[!] Ошибка разбора строки '{line}': {e}")

    def _parse_rule(self, line):
        parts = line.split()
        src_spec = "any"
        dst_spec = "any"

        if "source" in parts:
            i = parts.index("source")
            src_spec = self._parse_addr_with_wildcard(parts, i + 1)

        if "destination" in parts:
            i = parts.index("destination")
            dst_spec = self._parse_addr_with_wildcard(parts, i + 1)

        return [(src_spec, dst_spec)]

    def _parse_addr_with_wildcard(self, parts, idx):
        if idx >= len(parts):
            return "any"

        ip = parts[idx]

        wc = None
        if idx + 1 < len(parts):
            nxt = parts[idx + 1]
            if self._looks_like_wildcard(nxt):
                wc = nxt

        if wc is None:
            return f"{ip}/32"

        spec = self._wildcard_to_network_or_range(ip, wc)
        return spec

    def _looks_like_wildcard(self, s: str) -> bool:
        if s.count(".") == 3:
            try:
                ipaddress.IPv4Address(s)
                return True
            except ValueError:
                return False
        return s.isdigit()

    def _wildcard_to_network_or_range(self, ip_str: str, wildcard_str: str):
        try:
            if wildcard_str.count(".") == 3:
                w = int(ipaddress.IPv4Address(wildcard_str))
            else:
                w = int(wildcard_str)
                if not (0 <= w <= 0xFFFFFFFF):
                    raise ValueError("wildcard out of range")
        except Exception:
            return f"{ip_str}/32"

        if w == 0:
            return f"{ip_str}/32"

        if (w & (w + 1)) == 0:
            k = bin(w).count("1")
            prefix = 32 - k
            try:
                net = ipaddress.IPv4Network((ip_str, prefix), strict=True)
                return str(net)
            except ValueError:
                ip_int = int(ipaddress.IPv4Address(ip_str))
                start = (ip_int & (~w & 0xFFFFFFFF)) & 0xFFFFFFFF
                end = (ip_int | w) & 0xFFFFFFFF
                return ("range", ipaddress.IPv4Address(start), ipaddress.IPv4Address(end))

        ip_int = int(ipaddress.IPv4Address(ip_str))
        start = (ip_int & (~w & 0xFFFFFFFF)) & 0xFFFFFFFF
        end = (ip_int | w) & 0xFFFFFFFF
        return ("range", ipaddress.IPv4Address(start), ipaddress.IPv4Address(end))

    def _parse_search(self, text):
        if text == "any":
            return "any"
        if "/" in text:
            try:
                net = ipaddress.ip_network(text, strict=True)
                return str(net)
            except ValueError:
                return None
        if " " in text:
            parts = text.split()
            ip = parts[0]
            wc = parts[1]
            return self._wildcard_to_network_or_range(ip, wc)
        return f"{text}/32"

    def _get_min_max(self, spec):
        if spec == "any":
            return 0, 0xFFFFFFFF
        if spec is None:
            return None, None
        if isinstance(spec, tuple) and spec[0] == "range":
            _, start, end = spec
            return int(start), int(end)
        if "/" in spec:
            net = ipaddress.ip_network(spec, strict=False)
            return int(net.network_address), int(net.broadcast_address)
        ip = ipaddress.ip_address(spec)
        return int(ip), int(ip)

    def _spec_intersects(self, spec1, spec2, strict_mode):
        if spec1 is None or spec2 is None:
            return False

        if spec1 == "any" or spec2 == "any":
            if spec1 == spec2 == "any":
                return True
            return not strict_mode

        min1, max1 = self._get_min_max(spec1)
        min2, max2 = self._get_min_max(spec2)

        is_network1 = max1 > min1
        is_network2 = max2 > min2

        overlap = max1 >= min2 and max2 >= min1

        if is_network1:
            return min1 == min2 and max1 == max2

        if strict_mode:
            return min1 == min2 and max1 == max2

        return min2 <= min1 <= max2

    def find_acl_matches(self, src_ip, dst_ip, strict_mode=False):
        src_spec_search = self._parse_search(src_ip)
        dst_spec_search = self._parse_search(dst_ip)

        if src_spec_search is None or dst_spec_search is None:
            return []

        results = []
        for acl_key, rules in self.acls.items():
            matched_rules = []
            for rule_line, pairs in rules.items():
                for src_spec, dst_spec in pairs:
                    if self._spec_intersects(src_spec_search, src_spec, strict_mode) and self._spec_intersects(
                            dst_spec_search, dst_spec, strict_mode):
                        matched_rules.append(rule_line)
                        break
            if matched_rules:
                header = self.acl_headers.get(acl_key, f"acl {acl_key}")
                results.append(header)
                for r in matched_rules:
                    results.append(f"  {r}")
        return tuple(results)
class CiscoNexusParser:
    def __init__(self, lines):
        self.lines = lines
        self.object_groups = defaultdict(list)  # name -> [networks]
        self.acl_lines = []  # list of (acl_name, line)
        self.parse()

    def parse(self):
        current_group = None
        current_acl = None
        in_group = False
        in_acl = False
        current_values = []

        for line in self.lines:
            original_line = line  # Save for potential use
            line = line.strip()
            if not line:
                continue

            # Close group if starting a new top-level command
            if line.startswith("ip access-list") and in_group:
                self.object_groups[current_group] = current_values
                in_group = False
                current_group = None

            # Object-group parsing
            if line.startswith("object-group ip address"):
                if current_group:
                    self.object_groups[current_group] = current_values
                parts = line.split()
                current_group = parts[3] if len(parts) > 3 else parts[2]
                current_values = []
                in_group = True
                continue
            if in_group:
                parts = line.split()
                idx = 0
                if parts and parts[0].isdigit():  # Skip sequence
                    idx += 1
                if idx < len(parts):
                    entry = ' '.join(parts[idx:])
                    if entry.startswith("host"):
                        ip = entry.split()[1]
                        current_values.append(ip + "/32")
                    elif entry.startswith("network-object"):
                        subparts = entry.split()
                        if len(subparts) >= 3:
                            if subparts[1] == "host":
                                current_values.append(subparts[2] + "/32")
                            else:
                                try:
                                    addr_mask = ' '.join(subparts[1:])
                                    if '/' in addr_mask:
                                        net = ipaddress.ip_network(addr_mask, strict=False)
                                    else:
                                        net = ipaddress.ip_network((subparts[1], subparts[2]), strict=False)
                                    current_values.append(str(net))
                                except ValueError:
                                    pass
                    else:
                        # direct entry
                        parts_entry = entry.split()
                        if len(parts_entry) == 1:
                            if '/' in entry:
                                try:
                                    net = ipaddress.ip_network(entry, strict=False)
                                    current_values.append(str(net))
                                except ValueError:
                                    pass
                            elif self._is_ip_or_net(entry):
                                current_values.append(entry + "/32")
                        elif len(parts_entry) == 2:
                            if parts_entry[0] == "host":
                                current_values.append(parts_entry[1] + "/32")
                            else:
                                try:
                                    net = ipaddress.ip_network((parts_entry[0], parts_entry[1]), strict=False)
                                    current_values.append(str(net))
                                except ValueError:
                                    pass
                if line == "exit" or line == "}":
                    if current_group:
                        self.object_groups[current_group] = current_values
                    current_group = None
                    in_group = False
                    current_values = []
                continue

            # ACL parsing
            if line.startswith("ip access-list"):
                parts = line.split()
                if len(parts) >= 3:
                    current_acl = parts[2]
                    in_acl = True
                continue
            if in_acl:
                parts = line.split()
                if parts and (parts[0] in ["permit", "deny"] or (
                        parts[0].isdigit() and len(parts) > 1 and parts[1] in ["permit", "deny"])):
                    self.acl_lines.append((current_acl, original_line))  # Use original_line to preserve indentation
                elif line.startswith("statistics per-entry"):  # Ignore statistics
                    continue
                elif line == "exit" or line == "}":
                    in_acl = False
                    current_acl = None
                continue

        # Close any open sections at the end
        if in_group and current_group:
            self.object_groups[current_group] = current_values
        # No need for in_acl close, as lines are added

    @classmethod
    def from_local_file(cls, filename, src_ip=None, dst_ip=None, strict_mode=False, base_dir="collected_files_clear",
                        encoding="utf-8"):
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file == filename:
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "r", encoding=encoding, errors="ignore") as f:
                            lines = f.readlines()  # Use readlines to preserve original lines with indentation
                    except Exception as e:
                        print(f"[!] Ошибка чтения {full_path}: {e}")
                        continue
                    parser = cls(lines)
                    return parser.find_acl_matches(src_ip, dst_ip, strict_mode)
        print(f"⚠️ Файл {filename} не найден в директории {base_dir}")
        return []

    def _cand_to_net(self, cand):
        try:
            if isinstance(cand, str):
                if '/' in cand:
                    return ipaddress.ip_network(cand, strict=False)
                elif ' ' in cand:
                    parts = cand.split()
                    if len(parts) == 2:
                        return ipaddress.ip_network((parts[0], parts[1]), strict=False)
                else:
                    return ipaddress.ip_network(cand + '/32', strict=False)
            elif isinstance(cand, tuple) and len(cand) == 2:
                if cand[0] == cand[1]:
                    return ipaddress.ip_network(str(cand[0]) + '/32', strict=False)
        except ValueError:
            return None
        return None

    def _matches(self, input_str, candidates, strict_mode):
        if not input_str or input_str == "any":
            return True
        try:
            if '/' in input_str:
                input_net = ipaddress.ip_network(input_str, strict=False)
                for cand in candidates:
                    cand_net = self._cand_to_net(cand)
                    if cand_net:
                        if strict_mode:
                            if input_net == cand_net:
                                return True
                        else:
                            if input_net.overlaps(cand_net):
                                return True
                return False
            else:
                # IP
                input_ip = ipaddress.ip_address(input_str)
                input_net_32 = ipaddress.ip_network(f"{input_ip}/32", strict=False)
                for cand in candidates:
                    cand_net = self._cand_to_net(cand)
                    if cand_net:
                        if strict_mode:
                            if cand_net == input_net_32:
                                return True
                        else:
                            if input_ip in cand_net:
                                return True
                return False
        except ValueError:
            return False

    def _is_ip_or_net(self, s):
        try:
            if '/' in s:
                ipaddress.ip_network(s, strict=False)
            else:
                ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    def _is_port_operator(self, token):
        return token in ['eq', 'gt', 'lt', 'neq', 'range']

    def _extract_src_dst(self, parts):
        idx = 0
        # Skip sequence number
        if parts and parts[0].isdigit():
            idx += 1
        # Skip action (permit/deny)
        if idx < len(parts) and parts[idx] in ['permit', 'deny']:
            idx += 1
        # Skip protocol (ip, tcp, udp, icmp, etc.)
        if idx < len(parts) and parts[idx] not in ['any', 'host', 'object-group',
                                                   'addrgroup'] and not self._is_ip_or_net(parts[idx]):
            idx += 1

        def parse_entry(idx):
            if idx >= len(parts):
                return None, idx
            val = parts[idx]
            if val in ["object-group", "addrgroup"]:
                if idx + 1 < len(parts):
                    return parts[idx + 1], idx + 2
                return None, idx + 1
            elif val == "host":
                if idx + 1 < len(parts):
                    return f"{parts[idx + 1]}/32", idx + 2
                return None, idx + 1
            elif val == "any":
                return "any", idx + 1
            elif '/' in val:  # CIDR
                try:
                    net = ipaddress.ip_network(val, strict=False)
                    return str(net), idx + 1
                except ValueError:
                    return None, idx + 1
            elif self._is_ip_or_net(val):
                # Check for subnet mask or wildcard
                if idx + 1 < len(parts) and self._is_ip_or_net(parts[idx + 1]):
                    try:
                        net = ipaddress.ip_network((val, parts[idx + 1]), strict=False)
                        return str(net), idx + 2
                    except ValueError:
                        return f"{val}/32", idx + 1
                else:
                    return f"{val}/32", idx + 1
            return None, idx + 1

        # Parse src
        src_entry, idx = parse_entry(idx)

        # Skip src ports (eq X, range X Y, etc.), including symbolic ports
        while idx < len(parts) and self._is_port_operator(parts[idx]):
            op = parts[idx]
            idx += 1
            if op == 'range':
                # Skip two ports (numeric or symbolic)
                if idx < len(parts):
                    idx += 1  # first port
                if idx < len(parts):
                    idx += 1  # second port
            else:
                # eq/gt/lt/neq: skip one port
                if idx < len(parts):
                    idx += 1

        # Parse dst
        dst_entry, idx = parse_entry(idx)

        # Skip dst ports similarly
        while idx < len(parts) and self._is_port_operator(parts[idx]):
            op = parts[idx]
            idx += 1
            if op == 'range':
                if idx < len(parts):
                    idx += 1
                if idx < len(parts):
                    idx += 1
            else:
                if idx < len(parts):
                    idx += 1

        return src_entry, dst_entry

    def _resolve_entry(self, entry):
        if not entry or entry == "any":
            return ["any"]
        if "/" in entry or self._is_ip_or_net(entry):
            return [entry]
        if entry in self.object_groups:
            return self.object_groups[entry]
        return []

    def find_acl_matches(self, src_ip=None, dst_ip=None, strict_mode=False):
        matches = []
        current_acl = None
        for acl_name, line in self.acl_lines:
            parts = line.strip().split()  # Strip for parsing
            if len(parts) < 4:
                continue
            try:
                src_entry, dst_entry = self._extract_src_dst(parts)
                src_candidates = self._resolve_entry(src_entry)
                dst_candidates = self._resolve_entry(dst_entry)

                if src_candidates == ["any"] and dst_candidates == ["any"]:
                    continue

                src_ok = src_ip is None or self._matches(src_ip, src_candidates, strict_mode)
                dst_ok = dst_ip is None or self._matches(dst_ip, dst_candidates, strict_mode)

                if src_ok and dst_ok:
                    if acl_name != current_acl:
                        if current_acl is not None:  # Add empty line between ACLs
                            matches.append("")
                        matches.append(f"ip access-list {acl_name}")
                        current_acl = acl_name
                    matches.append(line.rstrip())  # Remove trailing \n
            except Exception as e:
                print(f"[!] Ошибка: {e} в строке: {line}")
                continue
        return tuple(matches)
class JuniperACLParser:
    def __init__(self, config_text):
        self.config_lines = config_text.splitlines()
        self.filters = defaultdict(dict)  # filter_name -> {term_name: list of rules}
        self.prefix_lists = defaultdict(list)  # prefix-list name -> [networks]
        self.address_book = defaultdict(list)  # address-book name -> [networks]
        self.parse()

    def parse(self):
        """
        Разбор firewall filter в конфигурации Juniper.
        Сохраняет только те filter/term, где then = accept / discard / reject.
        """
        current_filter = None
        current_term = None
        current_sources = []
        current_dests = []
        current_action = None
        in_from = False
        in_source_address = False
        in_destination_address = False
        in_then = False

        for line in self.config_lines:
            line = line.strip()

            # Пропускаем пустые строки
            if not line:
                continue

            # Начало нового filter
            if line.startswith("filter "):
                parts = line.split()
                if len(parts) >= 2 and parts[1] != "{":
                    current_filter = parts[1]
                    self.filters[current_filter] = {}
                continue

            # Начало term
            if line.startswith("term "):
                parts = line.split()
                if len(parts) >= 2 and parts[1] != "{":
                    current_term = parts[1]
                    current_sources, current_dests, current_action = [], [], None
                    in_from = False
                    in_source_address = False
                    in_destination_address = False
                    in_then = False
                continue

            # Начало from {
            if line == "from {":
                in_from = True
                continue

            # Начало source-address {
            if line == "source-address {" and in_from:
                in_source_address = True
                continue

            # Начало destination-address {
            if line == "destination-address {" and in_from:
                in_destination_address = True
                continue

            # IP в source-address
            if in_source_address and line.endswith(";"):
                ip = line.replace(";", "").strip()
                if ip:
                    current_sources.append(ip)
                continue

            # IP в destination-address
            if in_destination_address and line.endswith(";"):
                ip = line.replace(";", "").strip()
                if ip:
                    current_dests.append(ip)
                continue

            # Начало then { или then accept;
            if line.startswith("then"):
                if line == "then {":
                    in_then = True
                else:
                    # Прямой then accept;
                    action_part = line.split("then")[1].strip().replace(";", "")
                    if action_part in ("accept", "discard", "reject"):
                        current_action = action_part
                continue

            # Action внутри then {
            if in_then and line.endswith(";"):
                action = line.replace(";", "").strip()
                if action in ("accept", "discard", "reject"):
                    current_action = action
                continue

            # Закрывающие скобки }
            if line == "}":
                if in_source_address:
                    in_source_address = False
                elif in_destination_address:
                    in_destination_address = False
                elif in_from:
                    in_from = False
                elif in_then:
                    in_then = False
                elif current_term and current_action:
                    # Закрытие term
                    if current_term not in self.filters[current_filter]:
                        self.filters[current_filter][current_term] = []
                    self.filters[current_filter][current_term].append(
                        {"term": current_term,
                         "src": current_sources or ["any"],
                         "dst": current_dests or ["any"],
                         "action": current_action}
                    )
                    current_term, current_sources, current_dests, current_action = None, [], [], None
                    in_from = False
                    in_source_address = False
                    in_destination_address = False
                    in_then = False

    def _cand_to_net(self, cand):
        try:
            return ipaddress.ip_network(cand, strict=False)
        except ValueError:
            return None

    def _matches(self, input_str, ip_list, strict_mode):
        if input_str == "any":
            return True

        try:
            if '/' in input_str:  # network
                input_net = ipaddress.ip_network(input_str, strict=False)
                for net in ip_list:
                    if net == "any":
                        if strict_mode:
                            continue
                        else:
                            return True
                    cand_net = self._cand_to_net(net)
                    if cand_net and cand_net == input_net:
                        return True
                return False
            else:  # IP
                ip_obj = ipaddress.ip_address(input_str)
                input_net_32 = ipaddress.ip_network(str(ip_obj) + '/32', strict=False)
                for net in ip_list:
                    if net == "any":
                        if strict_mode:
                            continue
                        else:
                            return True
                    if strict_mode:
                        cand_net = self._cand_to_net(net)
                        if cand_net and cand_net == input_net_32:
                            return True
                    else:
                        try:
                            if ip_obj in ipaddress.ip_network(net, strict=False):
                                return True
                        except ValueError:
                            continue
                return False
        except ValueError:
            return False

    def find_acl_matches(self, src_ip, dst_ip, strict_mode=False):
        if dst_ip not in (None, "any") and strict_mode:
            return tuple()  # No strict match for dst in Juniper ACLs
        results = []
        for filt, terms in self.filters.items():
            if filt == "None":  # Игнорируем фильтр с именем None
                continue
            matched = []
            for term, rules in terms.items():
                for rule in rules:
                    if not rule["action"]:
                        continue
                    # Пропускаем правила с src=any и dst=any
                    if rule["src"] == ["any"] and rule["dst"] == ["any"]:
                        continue
                    src_ok = self._matches(src_ip, rule["src"], strict_mode)
                    dst_ok = self._matches(dst_ip, rule["dst"], strict_mode)
                    if src_ok and dst_ok:
                        src = ", ".join(rule["src"]) if rule["src"] != ["any"] else "any"
                        dst = ", ".join(rule["dst"]) if rule["dst"] != ["any"] else "any"
                        matched.append(f"term {term} {rule['action']} ip source {src} destination {dst}")
            if matched:
                results.append(f"filter {filt}:")
                results.extend("  " + m for m in matched)
        return tuple(results)

    @classmethod
    def from_local_file(cls, filename, src_ip, dst_ip, strict_mode=False, base_dir="collected_files_clear",
                        encoding="utf-8"):
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file == filename:
                    full_path = os.path.join(root, file)
                    with open(full_path, "r", encoding=encoding, errors="ignore") as f:
                        config_text = f.read()
                    parser = cls(config_text)
                    return tuple(parser.find_acl_matches(src_ip, dst_ip, strict_mode))
        print(f"⚠️ Файл {filename} не найден в директории {base_dir}")
        return tuple()
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
        if dst_ip not in (None, "any") and strict_mode:
            return set()  # No strict match for dst in Eltex ACLs

        matches = []
        for acl, rules in self.acls.items():
            matched_rules = []
            for rule in rules:
                if src_ip == "any" or self._match(src_ip, rule["source"], strict_mode):
                    matched_rules.append(f" {rule['raw']}")  # Add space before rule
            if matched_rules:  # Only include ACL if it has matching rules
                matches.append(f"management access-list {acl}\n" + "\n".join(matched_rules))
        return set(matches)

    @classmethod
    def from_local_file(cls, filename, src_ip, dst_ip=None,
                        strict_mode=False, base_dir="collected_files_clear", encoding="utf-8"):
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file == filename:
                    with open(os.path.join(root, file), "r", encoding=encoding, errors="ignore") as f:
                        parser = cls(f.read())
                        return parser.find_matches(src_ip, dst_ip, strict_mode)
        return set()