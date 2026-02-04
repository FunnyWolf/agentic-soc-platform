import base64
import datetime
import ipaddress
import json
import os
import random
import re
import shlex
import socket
import string
import subprocess
import time
import uuid
from collections import OrderedDict
from io import BytesIO
from urllib.parse import urlparse

import dns.resolver
import tldextract
from openpyxl import Workbook
from openpyxl import load_workbook
from openpyxl.utils.exceptions import InvalidFileException


def timestamp_to_string(timestamp, format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    """
    current_timestamp = 1672531200  # 对应 2023-01-01 00:00:00

    # 转换为默认格式的时间字符串
    time_string_default = timestamp_to_string(current_timestamp)

    # 转换为带毫秒的格式
    time_string_with_ms = timestamp_to_string(current_timestamp, "%Y-%m-%d %H:%M:%S.%f")

    # 转换为只包含日期和时区的格式
    time_string_custom = timestamp_to_string(current_timestamp, "%Y/%m/%d %Z")

    """
    dt_object = datetime.datetime.fromtimestamp(timestamp)
    return dt_object.strftime(format_str)


def string_to_timestamp(time_string: str, format_str: str = "%Y-%m-%dT%H:%M:%S") -> int:
    """
    time_string = "2023-01-01 00:00:00"

    timestamp_result = string_to_timestamp(time_string)

    time_string_custom = "2023/12/25 10:30:00"
    timestamp_custom = string_to_timestamp(time_string_custom, "%Y/%m/%d %H:%M:%S")

    time_string = "2025-09-18T14:51:30Z"
    timestamp_result = string_to_timestamp(time_string, "%Y-%m-%dT%H:%M:%SZ")
    """
    dt_object = datetime.datetime.strptime(time_string, format_str)

    return int(dt_object.timestamp())


def string_to_string_time(time_string: str, from_format: str, to_format: str) -> str:
    """
    time_string = "2023-01-01 00:00:00"

    converted_time = string_to_string_time(time_string, "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %I:%M %p")
    """
    dt_object = datetime.datetime.strptime(time_string, from_format)
    return dt_object.strftime(to_format)


def get_current_timestamp() -> int:
    """
    current_ts = get_current_timestamp()
    """
    return int(time.time())


def get_current_time_str(format_str: str = "%Y-%m-%dT%H:%M:%SZ") -> str:
    """
    # 示例
    # 默认格式（UTC时间）
    current_time_str = get_current_time_str()

    # 自定义格式：年-月-日（本地时间，无Z标记）
    current_date_str = get_current_time_str("%Y-%m-%d")

    # 自定义格式：本地时间
    local_time_str = get_current_time_str("%Y-%m-%d %H:%M:%S")
    """
    use_utc = 'Z' in format_str
    if use_utc:
        return datetime.datetime.now(datetime.timezone.utc).strftime(format_str)
    else:
        return datetime.datetime.now().strftime(format_str)


def exec_system(cmd, **kwargs):
    cmd = " ".join(cmd)
    timeout = 4 * 60 * 60

    if kwargs.get('timeout'):
        timeout = kwargs['timeout']
        kwargs.pop('timeout')

    completed = subprocess.run(shlex.split(cmd), timeout=timeout, check=False, close_fds=True, **kwargs)

    return completed


def random_str(len):
    value = ''.join(random.sample(string.ascii_letters + string.digits, len))
    return value


def random_str_no_num(len):
    value = ''.join(random.sample(string.ascii_letters, len))
    return value


def random_int(num):
    """生成随机字符串"""
    return random.randint(1, num)


def is_json(data):
    try:
        json.loads(data)
        return True
    except Exception as E:
        return False


def is_ipaddress(ip_str):
    try:
        ip = ipaddress.IPv4Address(ip_str)
        return True
    except Exception as E:
        return False


def is_private_ip(ip_address: str) -> bool:
    # 私有 IP 地址段的 CIDR 列表
    # 注意：根据您的要求,不添加任何调试信息,如果有异常直接raise
    PRIVATE_NETWORKS = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
    ]

    try:
        ip = ipaddress.ip_address(ip_address)
    except ValueError as e:
        # 如果 ipaddress.ip_address 抛出异常,根据要求直接 raise
        return False

    # 检查是否为 IPv4 地址
    if not isinstance(ip, ipaddress.IPv4Address):
        # 仅处理 IPv4 地址,IPv6 地址不在此函数的内网判断范围
        return False

    # 遍历私有网络,检查 IP 是否在其中
    for network_cidr in PRIVATE_NETWORKS:
        network = ipaddress.ip_network(network_cidr)
        if ip in network:
            return True

    return False


def is_domain(url):
    regex = r"^([a-zA-Z]+:\/\/)?([\da-zA-Z\.-]+)\.([a-zA-Z]{2,6})([\/\w \.-]*)*\/?$"
    return True if re.match(regex, url) else False


def is_root_domain(domain):
    ext = tldextract.extract(domain)
    return ext.fqdn == domain and not ext.subdomain


def get_one_uuid_str():
    uuid_str = str(uuid.uuid1()).replace('-', "")[0:16]
    return uuid_str


def data_return(code=500, data=None,
                msg_zh="服务器发生错误,请检查服务器",
                msg_en="An error occurred on the server, please check the server."):
    return {'code': code, 'data': data, 'msg_zh': msg_zh, "msg_en": msg_en}


class UnicodeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.decode(encoding='utf-8', errors="ignore").encode(encoding='utf-8', errors="ignore")
        elif isinstance(obj, str):
            return obj.encode(encoding='utf-8', errors="ignore").decode(encoding='utf-8', errors="ignore")
        return json.JSONEncoder.default(self, obj)


class UnicodeDecoder(json.JSONDecoder):
    def decode(self, s):
        s = s.encode(encoding='utf-8', errors="ignore").decode(encoding='utf-8', errors="ignore")
        return super().decode(s)


def u_json_dumps(data):
    return json.dumps(data, cls=UnicodeEncoder)


def u_json_loads(data):
    return json.loads(data, cls=UnicodeDecoder)


def dqtoi(dq):
    """将字符串ip地址转换为int数字."""
    octets = dq.split(".")
    if len(octets) != 4:
        raise ValueError
    for octet in octets:
        if int(octet) > 255:
            raise ValueError
    return (int(octets[0]) << 24) + \
        (int(octets[1]) << 16) + \
        (int(octets[2]) << 8) + \
        (int(octets[3]))


def str_to_ips(ipstr):
    """字符串转ip地址列表"""
    iplist = []
    lines = ipstr.split(",")
    for raw in lines:
        if '/' in raw:
            addr, mask = raw.split('/')
            mask = int(mask)

            bin_addr = ''.join([(8 - len(bin(int(i))[2:])) * '0' + bin(int(i))[2:] for i in addr.split('.')])
            start = bin_addr[:mask] + (32 - mask) * '0'
            end = bin_addr[:mask] + (32 - mask) * '1'
            bin_addrs = [(32 - len(bin(int(i))[2:])) * '0' + bin(i)[2:] for i in
                         range(int(start, 2), int(end, 2) + 1)]

            dec_addrs = ['.'.join([str(int(bin_addr[8 * i:8 * (i + 1)], 2)) for i in range(0, 4)]) for bin_addr in
                         bin_addrs]

            iplist.extend(dec_addrs)

        elif '-' in raw:
            addr, end = raw.split('-')
            end = int(end)
            start = int(addr.split('.')[3])
            prefix = '.'.join(addr.split('.')[:-1])
            addrs = [prefix + '.' + str(i) for i in range(start, end + 1)]
            iplist.extend(addrs)
            return addrs
        else:
            iplist.extend([raw])
    return iplist


# 定义协议及其默认端口号
DEFAULT_PORTS = {
    'http': 80,
    'https': 443,
    'ftp': 21,
    'ssh': 22,
    'telnet': 23,
    'smtp': 25,
    'redis': 6379,
    # 你可以继续添加更多协议及其默认端口号
}


def parse_url_simple(url):
    parsed_url = urlparse(url)
    scheme = parsed_url.scheme
    # host = parsed_url.netloc
    host = parsed_url.hostname
    port = parsed_url.port or DEFAULT_PORTS.get(scheme, None)

    return scheme, host, port


def clean_record(ipdomain_port_list):
    new_list = []
    for item in ipdomain_port_list:
        ipdomain = item[0]
        port = item[1]
        new_list.append({"ipdomain": ipdomain, "port": port})

    return new_list


def get_list_common(list1, list2):
    # list1 = [{'name': 'a', 'age': 20}, {'name': 'b', 'age': 30}, {'name': 'c', 'age': 25}]
    # list2 = [{'name': 'b', 'age': 30}, {'name': 'c', 'age': 25}, {'name': 'd', 'age': 35}]

    intersect = [i for i in set(list1) & set(list2)]
    return intersect


def get_list_diff(list1, list2):
    # list1 = [{'name': 'a', 'age': 20}, {'name': 'b', 'age': 30}, {'name': 'c', 'age': 25}]
    # list2 = [{'name': 'b', 'age': 30}, {'name': 'c', 'age': 25}, {'name': 'd', 'age': 35}]
    list1 = list(list1)
    list2 = list(list2)
    for one in list2:
        if one in list1:
            list1.remove(one)
    return list1


def is_ipaddress_port_in_use(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((ip, port))
        except socket.error as e:
            if e.errno == 98:  # 地址已在使用
                return True
            else:
                raise e
        else:
            return False


def get_dns_cname(domain):
    try:
        # 创建一个DNS解析器
        resolver = dns.resolver.Resolver()

        # 查询CNAME记录
        cname = resolver.resolve(domain, 'CNAME')

        # 返回CNAME记录列表
        return [cname_record.to_text() for cname_record in cname]
    except dns.resolver.NXDOMAIN:
        pass

    except dns.resolver.NoAnswer:
        pass
    except Exception as e:
        pass

    return []


def get_dns_a(domain):
    try:
        # 创建一个DNS解析器
        resolver = dns.resolver.Resolver()

        # 查询CNAME记录
        A = resolver.resolve(domain, "A")

        # 返回CNAME记录列表
        return [a.to_text() for a in A]
    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer:
        pass
    except Exception as e:
        pass
    return []


def write_list_of_dict_to_excel_sheet(data_list: list[dict], file_path: str = '', sheet_name: str = None, return_content=False):
    """
    仅使用 openpyxl 库将字典列表中的数据写入指定的 XLSX 文件和 sheet.

    逻辑：
    - 如果 XLSX 文件存在,则打开文件,否则创建新的 Workbook.
    - 指定 sheet 如果存在,则覆盖(删除旧的,创建新的)；如果不存在,则创建.
    - 字典的 key 作为表头.
    - 当 return_content 为 True 时,不进行任何本地文件系统操作.

    Args:
        data_list: 列表,列表中的每个元素是一个字典(代表一行数据).
        file_path: XLSX 文件的完整路径和名称(仅在 return_content=False 时使用).
        sheet_name: 要写入的 sheet 的名称.
        return_content: 返回 Base64 编码的 Excel 内容.
    """
    if not data_list:
        return

    if not return_content and file_path and os.path.exists(file_path):
        try:
            workbook = load_workbook(file_path)
        except Exception as e:

            raise IOError(f"Error loading workbook from {file_path}: {e}")
    else:

        workbook = Workbook()

    final_sheet_name = sheet_name if sheet_name else 'Sheet1'  # 默认使用 'Sheet1'

    if final_sheet_name in workbook.sheetnames:
        del workbook[final_sheet_name]

    worksheet = workbook.create_sheet(title=final_sheet_name, index=0)

    header = list(data_list[0].keys())
    worksheet.append(header)

    for row_dict in data_list:
        row_values = [row_dict.get(key, '') for key in header]
        worksheet.append(row_values)

    if 'Sheet' in workbook.sheetnames:
        default_sheet = workbook['Sheet']
        if default_sheet.max_row == 1 and default_sheet.cell(1, 1).value is None:
            del workbook['Sheet']

    if return_content:

        file_stream = BytesIO()
        workbook.save(file_stream)
        file_stream.seek(0)

        excel_bytes = file_stream.getvalue()
        base64_content = base64.b64encode(excel_bytes).decode('utf-8')

        return base64_content
    else:

        if not file_path:
            raise ValueError("file_path cannot be empty when return_content is False")

        directory = os.path.dirname(file_path)
        if directory:
            os.makedirs(directory, exist_ok=True)

        try:
            workbook.save(file_path)
        except Exception as e:
            raise IOError(f"Error saving workbook to {file_path}: {e}")
        return None


def read_excel_sheet_to_list_of_dict(file_path: str, sheet_name: str) -> list[dict]:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"文件不存在: {file_path}")

    data_list = []

    try:
        workbook = load_workbook(file_path, data_only=True)
    except InvalidFileException as e:
        raise InvalidFileException(f"文件格式无效或无法打开: {e}")
    except Exception as e:
        raise Exception(f"加载文件时发生未知错误: {e}")

    if sheet_name not in workbook.sheetnames:
        raise ValueError(f"Sheet '{sheet_name}' 不存在于工作簿中.")

    worksheet = workbook[sheet_name]

    rows = worksheet.iter_rows(values_only=True)

    try:
        header_row = next(rows)
        headers = [str(cell_value).strip() if cell_value is not None else f'Column_{i + 1}'
                   for i, cell_value in enumerate(header_row)]

    except StopIteration:
        return data_list

    for row_values in rows:
        if all(v is None for v in row_values):
            continue

        row_dict = OrderedDict(zip(headers, row_values))

        data_list.append(row_dict)

    return data_list


def read_file_and_base64(file_path: str) -> dict:
    """
    读取指定路径的文件,并返回包含文件名称和文件内容base64编码的字典.

    :param file_path: 文件的完整路径.
    :return: 包含文件名称和文件内容base64编码的字典,
             格式为 {"name": "文件名称,带后缀", "base64": "文件内容的base64编码"}.
    :raises FileNotFoundError: 如果文件路径不存在.
    :raises IOError: 如果读取文件时发生其他I/O错误.
    :raises Exception: 如果发生其他意外错误.
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件未找到: {file_path}")

        # 获取文件名称(带后缀)
        file_name = os.path.basename(file_path)

        # 读取文件内容并进行base64编码
        with open(file_path, 'rb') as f:
            file_content = f.read()
            # 使用标准的base64编码
            base64_encoded_content = base64.b64encode(file_content).decode('utf-8')

        # 返回字典
        return {
            "name": file_name,
            "base64": base64_encoded_content
        }

    except FileNotFoundError as e:
        # 直接raise异常,不包含调试信息
        raise e
    except IOError as e:
        # 直接raise异常,不包含调试信息
        raise IOError(f"读取文件时发生I/O错误: {e}")
    except Exception as e:
        # 直接raise异常,不包含调试信息
        raise Exception(f"发生未知错误: {e}")


def generate_four_random_timestamps(
        days_ago_max: int = 10,
        min_delta_2: int = 0,
        max_delta_2: int = 10,  # T2 在 T1 之后 0 到 10 分钟内
        min_delta_3: int = 0,
        max_delta_3: int = 30,  # T3 在 T2 之后 0 到 30 分钟内
        min_delta_4: int = 0,
        max_delta_4: int = 12 * 60,  # T4 在 T3 之后 0 到 12 小时内 (转换为分钟)
) -> dict:
    """
    生成四个满足指定时间间隔和格式的随机时间戳.

    Args:
        days_ago_max: 第一个时间点 T1 最多在当前时间之前的天数(可配置).
        min_delta_2, max_delta_2: T2 相对于 T1 的最小/最大分钟间隔.
        min_delta_3, max_delta_3: T3 相对于 T2 的最小/最大分钟间隔.
        min_delta_4, max_delta_4: T4 相对于 T3 的最小/最大分钟间隔(以分钟计).

    Returns:
        包含四个格式化时间戳的字典.
    """

    # 1. 定义时间戳格式
    # %Y-%m-%dT%H:%M:%SZ 格式对应 ISO 8601,其中 'Z' 表示 UTC/Zulu time
    TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

    # 2. 获取当前的 UTC 时间作为基准时间
    # 使用 UTC 时间可以避免时区和夏令时问题
    now_utc = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)

    # --- 生成 T1 (当前时间点之前 [0, days_ago_max] 天内随机的一个时间) ---

    # 计算 T1 的时间范围：[now_utc - days_ago_max 天, now_utc]
    start_t1 = now_utc - datetime.timedelta(days=days_ago_max)

    # 将时间范围转换为秒数(时间戳)
    time_diff_seconds = int((now_utc - start_t1).total_seconds())

    # 生成一个 T1 之前的随机秒数
    random_seconds_t1 = random.randint(0, time_diff_seconds)

    # 计算 T1
    t1 = start_t1 + datetime.timedelta(seconds=random_seconds_t1)

    # --- 生成 T2 (T1 之后 [min_delta_2, max_delta_2] 分钟内随机的一个时间) ---

    # 随机选择一个分钟间隔
    random_minutes_t2 = random.randint(min_delta_2, max_delta_2)
    # 计算 T2
    t2 = t1 + datetime.timedelta(minutes=random_minutes_t2)

    # --- 生成 T3 (T2 之后 [min_delta_3, max_delta_3] 分钟内随机的一个时间) ---

    # 随机选择一个分钟间隔
    random_minutes_t3 = random.randint(min_delta_3, max_delta_3)
    # 计算 T3
    t3 = t2 + datetime.timedelta(minutes=random_minutes_t3)

    # --- 生成 T4 (T3 之后 [min_delta_4, max_delta_4] 分钟内随机的一个时间) ---

    # 随机选择一个分钟间隔
    random_minutes_t4 = random.randint(min_delta_4, max_delta_4)
    # 计算 T4
    t4 = t3 + datetime.timedelta(minutes=random_minutes_t4)

    # 3. 格式化输出
    # strftime("%Y-%m-%dT%H:%M:%SZ") 将 datetime 对象格式化为所需字符串
    result = {
        "alert_date": t1.strftime(TIME_FORMAT),
        "created_date": t2.strftime(TIME_FORMAT),
        "acknowledged_date": t3.strftime(TIME_FORMAT),
        "closed_date": t4.strftime(TIME_FORMAT),
    }

    return result
