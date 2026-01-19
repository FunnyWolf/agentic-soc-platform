from __future__ import annotations

from typing import Dict
from typing import List, Any

import requests
from requests.adapters import HTTPAdapter

from Lib.log import logger
from Lib.xcache import Xcache
from PLUGINS.SIRP.CONFIG import SIRP_URL, SIRP_APPKEY, SIRP_SIGN
from PLUGINS.SIRP.nocolymodel import FieldType, OptionType

# SESSION
HEADERS = {"HAP-Appkey": SIRP_APPKEY,
           "HAP-Sign": SIRP_SIGN}

SIRP_REQUEST_TIMEOUT = 10  # seconds

HTTP_SESSION = requests.Session()
HTTP_SESSION.headers.update(HEADERS)
HTTP_SESSION.verify = False
adapter = HTTPAdapter(
    pool_connections=10,
    pool_maxsize=10
)
HTTP_SESSION.mount('http://', adapter)
HTTP_SESSION.mount('https://', adapter)

SYSTEM_FIELDS = ['rowid', 'ownerid', 'caid', 'ctime', 'utime', 'uaid', 'wfname', 'wfcuaids', 'wfcaid', 'wfctime', 'wfrtime', 'wfcotime', 'wfdtime', 'wfftime',
                 'wfstatus']


class Worksheet(object):
    def __init__(self):
        pass

    @staticmethod
    def get_fields(worksheet_id: str) -> Dict[str, FieldType]:
        cached_fields = Xcache.get_sirp_fields(worksheet_id)
        if cached_fields is not None:
            return cached_fields

        url = f"{SIRP_URL}/api/v3/app/worksheets/{worksheet_id}"

        response = HTTP_SESSION.get(
            url
        )
        response.raise_for_status()

        response_data = response.json()
        if response_data.get("success"):
            fields_list: List[FieldType] = response_data.get("data").get("fields")
            fields_dict = {}
            for field in fields_list:
                if field["id"] not in SYSTEM_FIELDS:
                    fields_dict[field["alias"]] = field
                else:
                    fields_dict[field["id"]] = field
            Xcache.set_sirp_fields(worksheet_id, fields_dict)
            return fields_dict
        else:
            raise Exception(f"error_code: {response_data.get('error_code')} error_msg: {response_data.get('error_msg')}")


class WorksheetRow(object):
    def __init__(self):
        pass

    @staticmethod
    def get(worksheet_id: str, row_id: str, include_system_fields=True) -> dict:
        url = f"{SIRP_URL}/api/v3/app/worksheets/{worksheet_id}/rows/{row_id}"
        fields = Worksheet.get_fields(worksheet_id)
        response = HTTP_SESSION.get(
            url,
            timeout=SIRP_REQUEST_TIMEOUT,
            params={"includeSystemFields": include_system_fields}
        )
        response.raise_for_status()

        response_data = response.json()
        if response_data.get("success"):
            row = response_data.get("data")
            data_new = WorksheetRow._format_input_row(row, fields, include_system_fields)
            return data_new
        else:
            raise Exception(f"error_code: {response_data.get('error_code')} error_msg: {response_data.get('error_msg')}")

    @staticmethod
    def _format_input_row(row, fields, include_system_fields=True) -> dict:
        data_new = {}
        for alias in row:
            if alias in SYSTEM_FIELDS:
                if include_system_fields or alias == "rowid":
                    data_new[alias] = row[alias]
                else:
                    continue
            else:
                field = fields.get(alias)
                if field is None:
                    logger.warning(f"field {alias} not found in fields")
                    continue
                data_new[alias] = WorksheetRow._format_input_value(field, row[alias])
        return data_new

    @staticmethod
    def _format_input_value(field, value):
        field_type = field.get("type")
        sub_type = field.get("subType")
        if field_type in ["MultipleSelect"]:
            value_list = []
            for option in value:
                value_list.append(option.get("value"))
            return value_list
        elif field_type in ['SingleSelect', "Dropdown"]:
            if len(value) > 0:
                return value[0].get("value")
            else:
                return None
        elif field_type in ['Relation']:
            if sub_type == 1:
                value_list = []
                for option in value:
                    value_list.append(option.get("sid"))
                return value_list
            else:
                return value
        elif field_type in ['Checkbox']:
            return bool(int(value))
        else:
            return value

    @staticmethod
    def _format_output_value(fields_config, fields):
        fields_new = []
        for field in fields:
            field_key = field.get("id")
            field_config = fields_config.get(field_key)
            if not field_config:
                for f in fields_config.values():
                    if f.get("id") == field_key:
                        field_config = f
                        break
            if not field_config:
                continue

            field_type = field_config.get("type")
            sub_type = field_config.get("subType")
            value = field.get("value")

            if field_type in ['Checkbox']:
                fields_new.append({
                    "id": field_key,
                    "value": 1 if value else 0
                })
            else:
                fields_new.append(field)
        return fields_new

    @staticmethod
    def translate_filter_names_to_ids(filter_data, fields_config):
        if filter_data.get("type") == "group":
            for child in filter_data.get("children", []):
                WorksheetRow.translate_filter_names_to_ids(child, fields_config)

        elif filter_data.get("type") == "condition":
            if filter_data.get("operator") == "in" and isinstance(filter_data.get("value"), list):
                field_key = filter_data.get("field")

                target_field = fields_config.get(field_key)
                if not target_field:
                    for f in fields_config.values():
                        if f.get("id") == field_key:
                            target_field = f
                            break

                if target_field and target_field.get("options"):
                    value_to_key = {opt["value"]: opt["key"] for opt in target_field["options"]}
                    filter_data["value"] = [value_to_key.get(v, v) for v in filter_data["value"]]

    @staticmethod
    def list(worksheet_id: str, filter: dict, include_system_fields=True) -> List:
        url = f"{SIRP_URL}/api/v3/app/worksheets/{worksheet_id}/rows/list"
        all_rows = []
        page_index = 1
        page_size = 1000
        fields_config = Worksheet.get_fields(worksheet_id)
        WorksheetRow.translate_filter_names_to_ids(filter, fields_config)
        while True:
            data = {
                "filter": filter,
                "sorts": [
                    {
                        "field": "utime",
                        "isAsc": False
                    }
                ],
                "includeTotalCount": True,
                "pageSize": page_size,
                "pageIndex": page_index
            }

            response = HTTP_SESSION.post(url,
                                         timeout=SIRP_REQUEST_TIMEOUT,
                                         headers=HEADERS,
                                         json=data)
            response.raise_for_status()
            response_data = response.json()

            if not response_data.get("success"):
                raise Exception(f"error_code: {response_data.get('error_code')} error_msg: {response_data.get('error_msg')}")

            result_data = response_data.get("data")
            rows = result_data.get("rows")
            total_count = result_data.get("total", 0)

            if not rows:
                break

            for row in rows:
                formatted_row = WorksheetRow._format_input_row(row, fields_config, include_system_fields)
                all_rows.append(formatted_row)

            if len(all_rows) >= total_count:
                break

            page_index += 1

        return all_rows

    @staticmethod
    def create(worksheet_id: str, fields: List, trigger_workflow: bool = True):
        # fields = [
        #     field for field in fields if field.get("value") is not None and field.get("value") != ""
        # ]

        url = f"{SIRP_URL}/api/v3/app/worksheets/{worksheet_id}/rows"
        fields_config = Worksheet.get_fields(worksheet_id)
        fields = WorksheetRow._format_output_value(fields_config, fields)
        data = {
            "triggerWorkflow": trigger_workflow,
            "fields": fields
        }

        try:
            response = HTTP_SESSION.post(url,
                                         timeout=SIRP_REQUEST_TIMEOUT,
                                         json=data)
            response.raise_for_status()

            response_data = response.json()
            if response_data.get("success"):
                return response_data.get("data").get("id")
            else:
                raise Exception(f"error_code: {response_data.get('error_code')} error_msg: {response_data.get('error_msg')} data: {response_data.get('data')}")
        except Exception as e:
            raise e

    @staticmethod
    def update(worksheet_id: str, row_id: str, fields: List, trigger_workflow: bool = True):

        # fields = [
        #     field for field in fields if field.get("value") is not None
        # ]

        fields_config = Worksheet.get_fields(worksheet_id)
        fields = WorksheetRow._format_output_value(fields_config, fields)
        url = f"{SIRP_URL}/api/v3/app/worksheets/{worksheet_id}/rows/{row_id}"

        data = {
            "triggerWorkflow": trigger_workflow,
            "fields": fields
        }
        response = HTTP_SESSION.patch(url,
                                      timeout=SIRP_REQUEST_TIMEOUT,
                                      json=data)
        response.raise_for_status()

        response_data = response.json()
        if response_data.get("success"):
            return response_data.get("data")
        else:
            raise Exception(f"error_code: {response_data.get('error_code')} error_msg: {response_data.get('error_msg')}")

    @staticmethod
    def delete(worksheet_id: str, row_ids: List, trigger_workflow: bool = True):

        url = f"{SIRP_URL}/api/v3/app/worksheets/{worksheet_id}/rows/batch"

        data = {
            "rowids": row_ids,
            "triggerWorkflow": trigger_workflow,
        }

        response = HTTP_SESSION.delete(url,
                                       timeout=SIRP_REQUEST_TIMEOUT,
                                       json=data)
        response.raise_for_status()

        response_data = response.json()
        if response_data.get("success"):
            return response_data.get("data")
        else:
            raise Exception(f"error_code: {response_data.get('error_code')} error_msg: {response_data.get('error_msg')}")

    @staticmethod
    def relations(worksheet_id: str, row_id: str, field: str, relation_worksheet_id: str, include_system_fields: bool = True, page_size: int = 1000,
                  page_index: int = 1):
        fields = Worksheet.get_fields(relation_worksheet_id)

        url = f"{SIRP_URL}/api/v3/app/worksheets/{worksheet_id}/rows/{row_id}/relations/{field}"

        params = {}
        if page_size is not None:
            params["pageSize"] = page_size
        if page_index is not None:
            params["pageIndex"] = page_index
        if include_system_fields is not None:
            params["isReturnSystemFields"] = include_system_fields

        response = HTTP_SESSION.get(url,
                                    timeout=SIRP_REQUEST_TIMEOUT,
                                    params=params)
        response.raise_for_status()

        response_data = response.json()
        if response_data.get("success"):
            rows = response_data.get("data").get("rows")
            rows_new = []
            for row in rows:
                data_new = WorksheetRow._format_input_row(row, fields, include_system_fields)
                rows_new.append(data_new)
            return rows_new
        else:
            raise Exception(f"error_code: {response_data.get('error_code')} error_msg: {response_data.get('error_msg')}")

    @staticmethod
    def get_rowid_list_from_rowid(rowid):
        # 多行数据获取列表
        tmp = rowid.split("_")
        rowid_list = tmp[0].split(",")
        return rowid_list


class OptionSet(object):
    def __init__(self):
        pass

    @staticmethod
    def list():
        cached_optionsets = Xcache.get_sirp_optionset()
        if cached_optionsets is not None:
            return cached_optionsets
        url = f"{SIRP_URL}/api/v3/app/optionsets"

        response = HTTP_SESSION.get(url,
                                    timeout=SIRP_REQUEST_TIMEOUT)
        response.raise_for_status()

        response_data = response.json()
        if response_data.get("success"):
            optionsets: List[Dict[str, Any]] = response_data.get("data").get("optionsets")
            Xcache.set_sirp_optionset(optionsets)
            return optionsets
        else:
            raise Exception(f"error_code: {response_data.get('error_code')} error_msg: {response_data.get('error_msg')}")

    @staticmethod
    def get(name):
        optionsets = OptionSet.list()
        for optionset in optionsets:
            if optionset["name"] == name:
                options = optionset.get("options", [])
                return options
        raise Exception(f"optionset {name} not found")

    @staticmethod
    def get_option_by_name_and_value(name, value) -> OptionType:
        optionsets = OptionSet.list()
        for optionset in optionsets:
            if optionset["name"] == name:
                options = optionset.get("options", [])
                for option in options:
                    if option["value"] == value:
                        return option
        raise Exception(f"optionset {name} {value} not found")

    @staticmethod
    def get_option_key_by_name_and_value(name, value):
        optionsets = OptionSet.list()
        for optionset in optionsets:
            if optionset["name"] == name:
                options = optionset.get("options", [])
                for option in options:
                    if option["value"] == value:
                        return option["key"]
        raise Exception(f"optionset {name} {value} not found")
