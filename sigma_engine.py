import yaml
import re
import logging
import os
import argparse
import base64
import datetime
import ipaddress
from typing import Dict, List, Union, Tuple

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

class UnifiedSIEMEngine:
    def __init__(self, definition_file: str):
        self.definitions = self.load_yaml_file(definition_file)
        self.modifier_handlers = {
            "contains": self._handle_contains,
            "startswith": self._handle_startswith,
            "endswith": self._handle_endswith,
            "re": self._handle_regex,
            "equals": self._handle_equals,
            "exists": self._handle_exists,
            "base64": self._handle_base64,
            "base64offset": self._handle_base64offset,
            "expand": self._handle_expand,
            "windash": self._handle_windash,
            "cased": self._handle_cased,
            "lt": self._handle_lt, "lte": self._handle_lte,
            "gt": self._handle_gt, "gte": self._handle_gte,
            "minute": self._handle_minute,
            "hour": self._handle_hour,
            "day": self._handle_day,
            "week": self._handle_week,
            "month": self._handle_month,
            "year": self._handle_year,
            "cidr": self._handle_cidr,
            "fieldref": self._handle_fieldref,
        }
        self.encoding_handlers = {
            "utf16le": lambda v: v.encode('utf-16le'),
            "utf16be": lambda v: v.encode('utf-16be'),
            "utf16": lambda v: b'\xFF\xFE' + v.encode('utf-16le'),
            "wide": lambda v: v.encode('utf-16le'),
        }

    def load_yaml_file(self, path: str) -> dict:
        try:
            with open(path, 'r', encoding='utf-8') as file:
                return yaml.safe_load(file)
        except Exception as e:
            logging.error(f"Failed to load YAML file {path}: {e}")
            raise

    def map_field(self, siem_name: str, field: str) -> str:
        siem_def = self.definitions['siems'].get(siem_name, {})
        mappings = siem_def.get('field_mappings', {})
        mapped = mappings.get(field, field)
        if mapped == field and field not in siem_def.get('known_fields', []):
            logging.warning(f"Field '{field}' not mapped for {siem_name}")
        return mapped

    def escape_value(self, siem_name: str, value: str) -> str:
        siem_def = self.definitions['siems'].get(siem_name, {})
        escape_chars = siem_def.get('escape_chars', {})
        for char, replacement in escape_chars.items():
            value = value.replace(char, replacement)
        return value

    def format_value(self, siem_name: str, value: Union[str, List[str]], modifiers: List[str] = None) -> Union[str, List[str]]:
        if isinstance(value, list):
            return [self.format_value(siem_name, v, modifiers) for v in value]
        value = self.escape_value(siem_name, str(value))
        if value == 'null':
            return 'null'
        if modifiers:
            encoding = None
            for mod in modifiers:
                if mod in self.encoding_handlers:
                    encoding = mod
                elif mod in self.modifier_handlers and mod != 'all':
                    value = self.modifier_handlers[mod](siem_name, value, modifiers)
                elif mod not in {'all', 'i', 'm', 's'}:
                    logging.warning(f"Unsupported modifier '{mod}' for {siem_name}")
            if encoding:
                value = base64.b64encode(self.encoding_handlers[encoding](value)).decode('ascii')
        siem_def = self.definitions['siems'][siem_name]
        formatting_rule = siem_def.get('value_format', 'default')
        if formatting_rule == 'quote_if_space' and ' ' in value:
            return f'"{value}"'
        elif formatting_rule == 'always_quote':
            return f'"{value}"'
        return value

    # Modifier Handlers
    def _handle_contains(self, siem_name: str, value: str, mods: List[str]) -> str:
        return value

    def _handle_startswith(self, siem_name: str, value: str, mods: List[str]) -> str:
        return value

    def _handle_endswith(self, siem_name: str, value: str, mods: List[str]) -> str:
        return value.strip('\\')

    def _handle_regex(self, siem_name: str, value: str, mods: List[str]) -> str:
        return value

    def _handle_equals(self, siem_name: str, value: str, mods: List[str]) -> str:
        return value

    def _handle_exists(self, siem_name: str, value: str, mods: List[str]) -> str:
        return value  # Fixed: Return raw value, not boolean

    def _handle_base64(self, siem_name: str, value: str, mods: List[str]) -> str:
        return base64.b64encode(value.encode('ascii')).decode('ascii')

    def _handle_base64offset(self, siem_name: str, value: str, mods: List[str]) -> str:
        return value

    def _handle_expand(self, siem_name: str, value: str, mods: List[str]) -> str:
        if value.startswith('%') and value.endswith('%'):
            logging.warning(f"Placeholder '{value}' not expanded (requires pipeline)")
        return value

    def _handle_windash(self, siem_name: str, value: str, mods: List[str]) -> str:
        dashes = ['-', '/', '–', '—', '―']
        return '|'.join(value.replace('-', d) for d in dashes)

    def _handle_cased(self, siem_name: str, value: str, mods: List[str]) -> str:
        return value

    def _handle_lt(self, siem_name: str, value: str, mods: List[str]) -> str:
        return value

    def _handle_lte(self, siem_name: str, value: str, mods: List[str]) -> str:
        return value

    def _handle_gt(self, siem_name: str, value: str, mods: List[str]) -> str:
        return value

    def _handle_gte(self, siem_name: str, value: str, mods: List[str]) -> str:
        return value

    def _handle_minute(self, siem_name: str, value: str, mods: List[str]) -> str:
        return value

    def _handle_hour(self, siem_name: str, value: str, mods: List[str]) -> str:
        return value

    def _handle_day(self, siem_name: str, value: str, mods: List[str]) -> str:
        return value

    def _handle_week(self, siem_name: str, value: str, mods: List[str]) -> str:
        return value

    def _handle_month(self, siem_name: str, value: str, mods: List[str]) -> str:
        return value

    def _handle_year(self, siem_name: str, value: str, mods: List[str]) -> str:
        return value

    def _handle_cidr(self, siem_name: str, value: str, mods: List[str]) -> str:
        return value

    def _handle_fieldref(self, siem_name: str, value: str, mods: List[str]) -> str:
        return self.map_field(siem_name, value)

    def translate_search(self, siem_name: str, search_id: str, search: Union[dict, list]) -> str:
        siem_def = self.definitions['siems'].get(siem_name, {})
        operators = siem_def['operators']
        is_elastic = siem_name == "elasticsearch"
        if isinstance(search, list):
            conditions = [self._translate_dict(siem_name, item) if isinstance(item, dict) else [self.format_value(siem_name, item)]
                          for item in search]
            conditions = [cond[0] if len(cond) == 1 else siem_def['group_conditions']['any_of'].format(conditions=cond)
                          for cond in conditions]
            joiner = siem_def.get('joiner_any_of', ' OR ' if not is_elastic else ', ')
            result = siem_def['group_conditions']['any_of'].format(conditions=joiner.join(conditions))
        elif isinstance(search, dict):
            conditions = self._translate_dict(siem_name, search)
            joiner = siem_def.get('joiner_all_of', ' AND ' if not is_elastic else ', ')
            result = siem_def['group_conditions']['all_of'].format(conditions=joiner.join(conditions))
        else:
            raise ValueError(f"Invalid search structure for '{search_id}'")
        if is_elastic:
            return f'{{"query_string": {{"query": "{result}"}}}}'
        return result

    def _translate_dict(self, siem_name: str, search: dict) -> List[str]:
        siem_def = self.definitions['siems'][siem_name]
        operators = siem_def['operators']
        windash_strategy = siem_def.get('windash_strategy', 'regex')
        conditions = []
        for field, value in search.items():
            base_field = field.split('|')[0]
            mapped_field = self.map_field(siem_name, base_field)
            modifiers = field.split('|')[1:] if '|' in field else []
            operator_key = modifiers[0] if modifiers else 'equals'
            formatted_value = self.format_value(siem_name, value, modifiers)
            if operator_key == 'windash' and 'windash' in operators:
                windash_values = formatted_value.split('|')
                windash_templates = siem_def.get('windash_templates')
                if not windash_templates:
                    logging.error(f"SIEM '{siem_name}' supports 'windash' but lacks 'windash_templates' in definitions")
                    raise ValueError(f"Missing 'windash_templates' for {siem_name}")
                if windash_strategy == 'regex':
                    condition = windash_templates['regex'].format(field=mapped_field, value=formatted_value)
                elif windash_strategy == 'like':
                    sub_conditions = [operators['contains'].format(field=mapped_field, value=v) for v in windash_values]
                    condition = windash_templates['like'].format(conditions=' OR '.join(sub_conditions))
                else:
                    logging.warning(f"Unknown windash_strategy '{windash_strategy}' for {siem_name}, defaulting to regex")
                    condition = windash_templates['regex'].format(field=mapped_field, value=formatted_value)
            elif operator_key == 're' and 're' in operators:
                flags = ''
                if 'i' not in modifiers: flags += ' CASE_SENSITIVE'
                if 'm' in modifiers: flags += ' MULTILINE'
                if 's' in modifiers: flags += ' DOTALL'
                condition = operators['re'].format(field=mapped_field, value=formatted_value, flags=flags.strip())
            elif operator_key not in operators:
                logging.warning(f"Operator '{operator_key}' not supported for '{siem_name}', defaulting to 'equals'")
                condition = operators['equals'].format(field=mapped_field, value=formatted_value)
            elif 'cased' in modifiers and operator_key in {'equals', 'contains', 'startswith', 'endswith'}:
                condition = operators[operator_key].format(field=mapped_field, value=formatted_value, flags=' CASE_SENSITIVE')
            elif isinstance(formatted_value, list) and 'all' in [m.lower() for m in modifiers]:
                sub_conditions = [operators[operator_key].format(field=mapped_field, value=v) for v in formatted_value]
                condition = siem_def['group_conditions']['all_of'].format(conditions=' AND '.join(sub_conditions))
            elif isinstance(formatted_value, list):
                sub_conditions = [operators[operator_key].format(field=mapped_field, value=v) for v in formatted_value]
                condition = siem_def['group_conditions']['any_of'].format(conditions=' OR '.join(sub_conditions))
            elif operator_key in {'lt', 'lte', 'gt', 'gte', 'minute', 'hour', 'day', 'week', 'month', 'year'}:
                condition = operators.get(operator_key, operators['equals']).format(field=mapped_field, value=formatted_value)
            else:
                condition = operators[operator_key].format(field=mapped_field, value=formatted_value)
            conditions.append(condition)
        return conditions

    def _parse_expr(self, tokens: List[str], siem_name: str, detection: dict, siem_def: dict, i: int = 0) -> Tuple[str, int]:
        expr_parts = []
        is_elastic = siem_name == "elasticsearch"
        while i < len(tokens):
            token = tokens[i].lower()
            if token == '(':
                sub_expr, next_i = self._parse_expr(tokens, siem_name, detection, siem_def, i + 1)
                expr_parts.append(f"({sub_expr})" if not is_elastic else sub_expr)
                i = next_i
            elif token == ')':
                result = " ".join(expr_parts) if not is_elastic else f'"must": [{"".join(expr_parts)}]'
                return result, i + 1
            elif token in ('and', 'or'):
                expr_parts.append(token.upper() if not is_elastic else f'"{token}": [')
                i += 1
            elif token == 'not':
                expr_parts.append('NOT' if not is_elastic else '"must_not": [')
                i += 1
            elif token in ('1', 'all') and i + 1 < len(tokens) and tokens[i + 1].lower() == 'of':
                op, i = tokens[i], i + 2
                if i < len(tokens):
                    pattern = tokens[i]
                    matches = [sid for sid in detection if re.match(pattern.replace('*', '.*'), sid) and sid != 'condition']
                    if matches:
                        sub_conditions = [self.translate_search(siem_name, sid, detection[sid]) for sid in matches]
                        joiner = siem_def.get('joiner_any_of', ' OR ' if not is_elastic else ', ')
                        if op == 'all':
                            joiner = siem_def.get('joiner_all_of', ' AND ' if not is_elastic else ', ')
                        group_expr = siem_def['group_conditions']['any_of' if op == '1' else 'all_of'].format(conditions=joiner.join(sub_conditions))
                        expr_parts.append(group_expr if not is_elastic else f'{{"query_string": {{"query": "{group_expr}"}}}}')
                    i += 1
            elif token in detection and token != 'condition':
                expr_parts.append(self.translate_search(siem_name, token, detection[token]))
                i += 1
            else:
                expr_parts.append(tokens[i])
                i += 1
        result = " ".join(expr_parts) if not is_elastic else f'"must": [{"".join(expr_parts)}]'
        return result, i

    def parse_condition(self, siem_name: str, condition: str, detection: dict) -> str:
        siem_def = self.definitions['siems'][siem_name]
        tokens = condition.split()
        parsed_expr, _ = self._parse_expr(tokens, siem_name, detection, siem_def, 0)
        if siem_name == "elasticsearch":
            return f'{{"bool": {{{parsed_expr}}}}}'
        return parsed_expr

    def generate_time_filter(self, siem_name: str, time_range: str) -> str:
        siem_def = self.definitions['siems'][siem_name]
        time_filter_def = siem_def['time_filter']
        keyword = time_filter_def['keyword']
        value = time_filter_def['format'].get(time_range, time_filter_def['format']['default'])
        return f"{keyword}{value}"

    def generate_query(self, siem_name: str, sigma_rule: dict) -> str:
        siem_def = self.definitions['siems'].get(siem_name, {})
        logsource = sigma_rule.get('logsource', {})
        index_key = '_'.join(filter(None, [logsource.get('product'), logsource.get('category'), logsource.get('service')]))
        fields = siem_def['index_map'].get(index_key) or siem_def['index_map'].get(logsource.get('category', 'default'), siem_def.get('default_index', ''))
        detection = sigma_rule['detection']
        condition = detection['condition']
        if isinstance(condition, list):
            condition = ' OR '.join(condition)
        translated_conditions = self.parse_condition(siem_name, condition, detection)
        time_field = sigma_rule.get('time_field', siem_def.get('default_time_field', 'timestamp'))
        time_filter = self.generate_time_filter(siem_name, sigma_rule.get('time_range', 'last_24_hours')).format(time_field=time_field) if siem_def.get('include_time_filter', True) else ''
        if translated_conditions and time_filter:
            full_conditions = siem_def.get('joiner_all_of', ' AND ').join([translated_conditions, time_filter])
        else:
            full_conditions = translated_conditions or time_filter
        query_template = siem_def['query_template']
        template_vars = {
            "columns": sigma_rule.get('columns', siem_def.get('default_columns', '*')),
            "index": fields,
            "conditions": full_conditions,
            "time_filter": time_filter
        }
        if "{fields}" in query_template:
            template_vars["fields"] = fields
        try:
            return query_template.format(**template_vars)
        except KeyError as e:
            logging.error(f"Template variable missing for {siem_name}: {e}")
            raise

    def generate_query_from_file(self, siem_name: str, sigma_rule_file: str) -> str:
        sigma_rule = self.load_yaml_file(sigma_rule_file)
        return self.generate_query(siem_name, sigma_rule)

    def evaluate_field_condition(self, siem_name: str, field: str, condition_value: Union[str, List[str]], modifiers: List[str], event: dict) -> bool:
        mapped_field = self.map_field(siem_name, field)
        event_value = event.get(mapped_field, event.get(field))
        formatted_value = self.format_value(siem_name, condition_value, modifiers)
        
        eval_funcs = {
            'equals': lambda ev, cv: str(ev) == str(cv) if ev is not None else False,
            'contains': lambda ev, cv: str(cv) in str(ev) if ev is not None else False,
            'startswith': lambda ev, cv: str(ev).startswith(str(cv)) if ev is not None else False,
            'endswith': lambda ev, cv: str(ev).replace('\\', '/').endswith(str(cv).replace('\\', '/').strip('/')) if ev is not None else False,
            're': lambda ev, cv: bool(re.search(cv, str(ev), (re.I if 'i' in modifiers else 0) | (re.M if 'm' in modifiers else 0) | (re.S if 's' in modifiers else 0))) if ev is not None else False,
            'exists': lambda ev, cv: (ev is not None) == (str(cv).lower() in ('true', '1')),
            'base64': lambda ev, cv: str(ev) == cv if ev is not None else False,
            'windash': lambda ev, cv: any(re.search(re.escape(v), str(ev)) for v in cv.split('|')) if ev is not None else False,
            'lt': lambda ev, cv: float(ev) < float(cv) if ev is not None else False,
            'lte': lambda ev, cv: float(ev) <= float(cv) if ev is not None else False,
            'gt': lambda ev, cv: float(ev) > float(cv) if ev is not None else False,
            'gte': lambda ev, cv: float(ev) >= float(cv) if ev is not None else False,
            'minute': lambda ev, cv: int(datetime.datetime.strptime(ev, '%Y-%m-%dT%H:%M:%S.%fZ').minute) == int(cv) if ev else False,
            'hour': lambda ev, cv: int(datetime.datetime.strptime(ev, '%Y-%m-%dT%H:%M:%S.%fZ').hour) == int(cv) if ev else False,
            'day': lambda ev, cv: int(datetime.datetime.strptime(ev, '%Y-%m-%dT%H:%M:%S.%fZ').day) == int(cv) if ev else False,
            'week': lambda ev, cv: int(datetime.datetime.strptime(ev, '%Y-%m-%dT%H:%M:%S.%fZ').isocalendar()[1]) == int(cv) if ev else False,
            'month': lambda ev, cv: int(datetime.datetime.strptime(ev, '%Y-%m-%dT%H:%M:%S.%fZ').month) == int(cv) if ev else False,
            'year': lambda ev, cv: int(datetime.datetime.strptime(ev, '%Y-%m-%dT%H:%M:%S.%fZ').year) == int(cv) if ev else False,
            'cidr': lambda ev, cv: ipaddress.ip_address(ev) in ipaddress.ip_network(cv, strict=False) if ev and cv else False,
            'fieldref': lambda ev, cv: str(ev) == str(event.get(cv)) if ev is not None else False,
        }
        op = modifiers[0] if modifiers else 'equals'
        func = eval_funcs.get(op, eval_funcs['equals'])
        
        if 'cased' in modifiers and op in {'equals', 'contains', 'startswith', 'endswith'}:
            return func(event_value, formatted_value)
        elif op in {'equals', 'contains', 'startswith', 'endswith'}:
            return func(str(event_value).lower() if event_value else None, str(formatted_value).lower())
        
        if isinstance(formatted_value, list) and 'all' in [m.lower() for m in modifiers]:
            return all(func(event_value, val) for val in formatted_value)
        elif isinstance(formatted_value, list):
            return any(func(event_value, val) for val in formatted_value)
        return func(event_value, formatted_value)

    def evaluate_search_identifier(self, siem_name: str, search: Union[dict, list, str], event: dict) -> bool:
        if isinstance(search, dict):
            return all(self.evaluate_field_condition(siem_name, field.split('|')[0], value, field.split('|')[1:] if '|' in field else [], event)
                       for field, value in search.items())
        elif isinstance(search, list):
            return any(self.evaluate_search_identifier(siem_name, item, event) for item in search)
        elif isinstance(search, str):
            return any(search in str(val) for val in event.values())
        return False

    def evaluate_detection(self, siem_name: str, detection: dict, event: dict) -> bool:
        search_results = {key: self.evaluate_search_identifier(siem_name, cond, event) 
                         for key, cond in detection.items() if key != "condition"}
        condition_str = detection.get("condition", "")
        
        tokens = condition_str.split()
        eval_str = []
        i = 0
        while i < len(tokens):
            token = tokens[i].lower()
            if token == 'not' and i + 1 < len(tokens):
                i += 1
                next_token = tokens[i].lower()
                if next_token in ('1', 'all') and i + 2 < len(tokens) and tokens[i + 1].lower() == 'of':
                    i += 2
                    pattern = tokens[i] if i < len(tokens) else '*'
                    matches = [k for k in search_results if re.match(pattern.replace('*', '.*'), k)]
                    if next_token == '1':
                        result = not any(search_results[k] for k in matches)
                    else:  # 'all'
                        result = not all(search_results[k] for k in matches)
                    eval_str.append(str(result))
                elif next_token in search_results:
                    eval_str.append(str(not search_results[next_token]))
                else:
                    eval_str.extend(['not', next_token])
                i += 1
            elif token in ('1', 'all') and i + 1 < len(tokens) and tokens[i + 1].lower() == 'of':
                op, i = tokens[i], i + 2
                pattern = tokens[i] if i < len(tokens) else '*'
                matches = [k for k in search_results if re.match(pattern.replace('*', '.*'), k)]
                if op == '1':
                    result = any(search_results[k] for k in matches)
                else:  # 'all'
                    result = all(search_results[k] for k in matches)
                eval_str.append(str(result))
                i += 1
            elif token in search_results:
                eval_str.append(str(search_results[token]))
                i += 1
            else:
                eval_str.append(token)
                i += 1
        
        final_condition = ' '.join(eval_str)
        try:
            return eval(final_condition, {"__builtins__": {}}, {"True": True, "False": False, "and": lambda x, y: x and y, 
                                                               "or": lambda x, y: x or y, "not": lambda x: not x})
        except Exception as e:
            logging.error(f"Error evaluating condition '{final_condition}': {e}")
            return False

    def test_rule(self, siem_name: str, sigma_rule: dict) -> None:
        test_log = sigma_rule.get('test_log')
        if not test_log:
            print("No test_log provided in the rule.")
            return
            
        print("=== Testing Rule ===")
        print("Rule Title:", sigma_rule.get('title', 'Untitled'))
        print("Raw Test Log:", test_log)
        
        try:
            event = yaml.safe_load(test_log)
            if not isinstance(event, dict):
                raise ValueError("test_log must be a JSON/YAML object")
        except Exception as e:
            print(f"Error parsing test_log: {e}")
            return
            
        print("\nParsed Event:", event)
        detection = sigma_rule.get('detection', {})
        print("\nDetection Conditions:", detection)
        
        search_results = {}
        for key, condition in detection.items():
            if key != 'condition':
                result = self.evaluate_search_identifier(siem_name, condition, event)
                search_results[key] = result
                print(f"\nEvaluating '{key}': {result}")
                if isinstance(condition, dict):
                    for field, value in condition.items():
                        modifiers = field.split('|')[1:] if '|' in field else []
                        field_name = field.split('|')[0]
                        eval_result = self.evaluate_field_condition(siem_name, field_name, value, modifiers, event)
                        print(f"  {field}: {eval_result} (Expected: {value}, Got: {event.get(field_name)})")
        
        final_result = self.evaluate_detection(siem_name, detection, event)
        print(f"\nFinal Condition: {detection.get('condition')}")
        print("Evaluation Results:", search_results)
        print("\nTest Result:", "PASSED" if final_result else "FAILED")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate SIEM queries from Sigma rules.")
    parser.add_argument("siem", help="SIEM to generate query for (e.g., splunk, crowdstrike, elasticsearch, trino)")
    parser.add_argument("path", help="Path to a Sigma rule file or directory of rule files")
    parser.add_argument("--test", action="store_true", help="Test the rule against its provided test log")
    args = parser.parse_args()

    engine = UnifiedSIEMEngine("siem_definitions.yml")
    if os.path.isdir(args.path):
        rule_files = [f for f in os.listdir(args.path) if f.endswith('.yml')]
        if not rule_files:
            print(f"No .yml files found in directory: {args.path}")
        else:
            for rule_file in rule_files:
                full_path = os.path.join(args.path, rule_file)
                try:
                    if args.test:
                        sigma_rule = engine.load_yaml_file(full_path)
                        print(f"--- Testing rule: {rule_file} ---")
                        engine.test_rule(args.siem, sigma_rule)
                    else:
                        query = engine.generate_query_from_file(args.siem, full_path)
                        print(query)
                except Exception as e:
                    print(f"Error processing {rule_file}: {e}")
    elif os.path.isfile(args.path) and args.path.endswith('.yml'):
        try:
            if args.test:
                sigma_rule = engine.load_yaml_file(args.path)
                engine.test_rule(args.siem, sigma_rule)
            else:
                query = engine.generate_query_from_file(args.siem, args.path)
                print(query)
        except Exception as e:
            print(f"Error processing {args.path}: {e}")
    else:
        print(f"Invalid path: {args.path}. Must be a .yml file or a directory.")
