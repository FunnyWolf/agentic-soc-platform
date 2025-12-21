from typing import TypedDict, Literal, List, Union, Any, Dict

import requests

from PLUGINS.SIRP.CONFIG import SIRP_URL, SIRP_APPKEY, SIRP_SIGN

HEADERS = {"HAP-Appkey": SIRP_APPKEY,
           "HAP-Sign": SIRP_SIGN}

SIRP_REQUEST_TIMEOUT = 10  # seconds

HTTP_SESSION = requests.Session()
adapter = requests.adapters.HTTPAdapter(
    pool_connections=10,
    pool_maxsize=10
)
HTTP_SESSION.mount('http://', adapter)
HTTP_SESSION.mount('https://', adapter)

class FieldType(TypedDict):
    id: str
    name: str
    alias: str
    value: str
    desc: str
    type: str
    required: bool
    isHidden: bool
    isReadOnly: bool
    isHiddenOnCreate: bool
    isUnique: bool
    isTitle: bool
    remark: str


class OptionType(TypedDict):
    key: str
    value: str
    index: int
    score: float


# Define the recursive types first
class ConditionType(TypedDict):
    type: Literal["condition"]
    field: str
    operator: str
    value: Any


class GroupType(TypedDict):
    type: Literal["group"]
    logic: Literal["AND", "OR"]
    children: List[Union["GroupType", ConditionType]]


class Worksheet(object):
    def __init__(self):
        pass

    @staticmethod
    def get_fields(worksheet_id: str) -> Dict[str, FieldType]:

        url = f"{SIRP_URL}/api/v3/app/worksheets/{worksheet_id}"

        response = requests.get(
            url,
            params={"includeSystemFields": True},
            headers=HEADERS
        )
        response.raise_for_status()

        response_data = response.json()
        if response_data.get("success"):
            fields_list: List[FieldType] = response_data.get("data").get("fields")
            fields_dict = {}
            for field in fields_list:
                fields_dict[field["id"]] = field
            return fields_dict
        else:
            raise Exception(f"error_code: {response_data.get('error_code')} error_msg: {response_data.get('error_msg')}")


class WorksheetRow(object):
    def __init__(self):
        pass

    @staticmethod
    def get(worksheet_id: str, row_id: str, include_system_fields=True):
        url = f"{SIRP_URL}/api/v3/app/worksheets/{worksheet_id}/rows/{row_id}"
        fields = Worksheet.get_fields(worksheet_id)
        try:
            response = requests.get(
                url,
                timeout=SIRP_REQUEST_TIMEOUT,
                params={"includeSystemFields": include_system_fields},
                headers=HEADERS
            )
            response.raise_for_status()

            response_data = response.json()
            if response_data.get("success"):
                row = response_data.get("data")
                data_new = WorksheetRow._format_row(row, fields, include_system_fields)
                return data_new
            else:
                raise Exception(f"error_code: {response_data.get('error_code')} error_msg: {response_data.get('error_msg')}")
        except Exception as e:
            raise

    @staticmethod
    def _format_row(row, fields, include_system_fields=True):
        data_new = {}
        for key in row:
            if key.startswith("_"):
                if include_system_fields:
                    data_new[key] = row[key]
                else:
                    continue
            elif key == "rowId":
                data_new[key] = row[key]
            else:
                alias = fields.get(key).get('alias')
                data_new[alias] = WorksheetRow._format_value(fields.get(key), row[key])
        return data_new

    @staticmethod
    def _format_value(field, value):
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
    def list(worksheet_id: str, filter: dict, include_system_fields=True):
        url = f"{SIRP_URL}/api/v3/app/worksheets/{worksheet_id}/rows/list"
        data = {
            # "fields": fields,
            "filter": filter,
            "sorts": [
                {
                    "field": "utime",
                    "direction": "desc"
                }
            ],
            "includeTotalCount": True,
            "includeSystemFields": include_system_fields,
            # "useFieldIdAsKey": False,
            "pageSize": 1000,
        }
        try:
            response = HTTP_SESSION.post(url,
                                     timeout=SIRP_REQUEST_TIMEOUT,
                                     headers=HEADERS,
                                     json=data)
            response.raise_for_status()
            response_data = response.json()
            if response_data.get("success"):
                fields = Worksheet.get_fields(worksheet_id)
                rows = response_data.get("data").get("rows")
                rows_new = []
                for row in rows:
                    data_new = WorksheetRow._format_row(row, fields, include_system_fields)
                    rows_new.append(data_new)
                return rows_new
            else:
                raise Exception(f"error_code: {response_data.get('error_code')} error_msg: {response_data.get('error_msg')}")
        except Exception as e:
            raise

    @staticmethod
    def create(worksheet_id: str, fields: list, triggerWorkflow: bool = False):

        fields = [
            field for field in fields if field.get("value") is not None and field.get("value") != ""
        ]

        url = f"{SIRP_URL}/api/v3/app/worksheets/{worksheet_id}/rows"

        data = {
            "triggerWorkflow": triggerWorkflow,
            "fields": fields
        }

        try:
            response = requests.post(url,
                                     timeout=SIRP_REQUEST_TIMEOUT,
                                     headers=HEADERS,
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
    def update(worksheet_id: str, row_id: str, fields: list):

        fields = [
            field for field in fields if field.get("value") is not None
        ]
        url = f"{SIRP_URL}/api/v3/app/worksheets/{worksheet_id}/rows/{row_id}"

        data = {
            "triggerWorkflow": True,
            "fields": fields
        }

        try:
            response = requests.patch(url,
                                      timeout=SIRP_REQUEST_TIMEOUT,
                                      headers=HEADERS,
                                      json=data)
            response.raise_for_status()

            response_data = response.json()
            if response_data.get("success"):
                return response_data.get("data")
            else:
                raise Exception(f"error_code: {response_data.get('error_code')} error_msg: {response_data.get('error_msg')}")
        except Exception as e:
            raise

    @staticmethod
    def delete(worksheet_id: str, row_ids: list):

        url = f"{SIRP_URL}/api/v3/app/worksheets/{worksheet_id}/rows/batch"

        data = {
            "rowIds": row_ids,
            "triggerWorkflow": True,
        }

        try:
            response = requests.delete(url,
                                       timeout=SIRP_REQUEST_TIMEOUT,
                                       headers=HEADERS,
                                       json=data)
            response.raise_for_status()

            response_data = response.json()
            if response_data.get("success"):
                return response_data.get("data")
            else:
                raise Exception(f"error_code: {response_data.get('error_code')} error_msg: {response_data.get('error_msg')}")
        except Exception as e:
            raise

    @staticmethod
    def relations(worksheet_id: str, row_id: str, field: str, relation_worksheet_id: str, include_system_fields: bool = True, page_size: int = 1000,
                  page_index: int = None):
        fields = Worksheet.get_fields(relation_worksheet_id)

        url = f"{SIRP_URL}/api/v3/app/worksheets/{worksheet_id}/rows/{row_id}/relations/{field}"

        params = {}
        if page_size is not None:
            params["pageSize"] = page_size
        if page_index is not None:
            params["pageIndex"] = page_index
        if include_system_fields is not None:
            params["isReturnSystemFields"] = include_system_fields
        try:
            response = requests.get(url,
                                    timeout=SIRP_REQUEST_TIMEOUT,
                                    headers=HEADERS,
                                    params=params)
            response.raise_for_status()

            response_data = response.json()
            if response_data.get("success"):
                rows = response_data.get("data").get("rows")
                rows_new = []
                for row in rows:
                    data_new = WorksheetRow._format_row(row, fields, include_system_fields)
                    rows_new.append(data_new)
                return rows_new
            else:
                raise Exception(f"error_code: {response_data.get('error_code')} error_msg: {response_data.get('error_msg')}")
        except Exception as e:
            raise

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

        url = f"{SIRP_URL}/api/v3/app/optionsets"

        response = requests.get(url,
                                timeout=SIRP_REQUEST_TIMEOUT,
                                headers=HEADERS)
        response.raise_for_status()

        response_data = response.json()
        if response_data.get("success"):
            return response_data.get("data").get("optionsets")
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
