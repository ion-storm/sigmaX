import yaml
import re
import logging
import os
import argparse
import base64
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
            for modifier in modifiers:
                if modifier in self.modifier_handlers:
                    value = self.modifier_handlers[modifier](siem_name, value)
                elif modifier != 'all':  # Skip 'all' here, handle in _translate_dict
                    logging.warning(f"Unsupported modifier '{modifier}' for {siem_name}")
        siem_def = self.definitions['siems'][siem_name]
        formatting_rule = siem_def.get('value_format', 'default')
        if formatting_rule == 'quote_if_space' and ' ' in value:
            return f'"{value}"'
        elif formatting_rule == 'always_quote':
            return f'"{value}"'
        return value

    # Modifier Handlers
    def _handle_contains(self, siem_name: str, value: str) -> str:
        return value

    def _handle_startswith(self, siem_name: str, value: str) -> str:
        return value

    def _handle_endswith(self, siem_name: str, value: str) -> str:
        return value

    def _handle_regex(self, siem_name: str, value: str) -> str:
        return value

    def _handle_equals(self, siem_name: str, value: str) -> str:
        return value

    def _handle_exists(self, siem_name: str, value: str) -> str:
        return value

    def _handle_base64(self, siem_name: str, value: str) -> str:
        return value

    def _handle_base64offset(self, siem_name: str, value: str) -> str:
        return value

    def _handle_expand(self, siem_name: str, value: str) -> str:
        if value.startswith('%') and value.endswith('%'):
            logging.warning(f"Placeholder '{value}' not expanded (implement expansion logic)")
        return value

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
        conditions = []
        for field, value in search.items():
            base_field = field.split('|')[0]
            mapped_field = self.map_field(siem_name, base_field)
            modifiers = field.split('|')[1:] if '|' in field else []
            operator_key = modifiers[0] if modifiers else 'equals'
            if operator_key not in operators:
                logging.warning(f"Operator '{operator_key}' not supported for '{siem_name}', defaulting to 'equals'")
                operator_key = 'equals'
            formatted_value = self.format_value(siem_name, value, modifiers)
            if isinstance(formatted_value, list) and 'all' in [m.lower() for m in modifiers]:
                # Handle '|modifier|all' by applying the modifier to all values with AND
                sub_conditions = [operators[operator_key].format(field=mapped_field, value=v) for v in formatted_value]
                condition = siem_def['group_conditions']['all_of'].format(conditions=' AND '.join(sub_conditions))
            elif isinstance(formatted_value, list):
                sub_conditions = [operators[operator_key].format(field=mapped_field, value=v) for v in formatted_value]
                condition = siem_def['group_conditions']['any_of'].format(conditions=' OR '.join(sub_conditions))
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
            full_conditions = f"{translated_conditions} AND {time_filter}"
        else:
            full_conditions = translated_conditions or time_filter
        
        query_template = siem_def['query_template']
        template_vars = {
            "columns": sigma_rule.get('columns', siem_def.get('default_columns', '*')),
            "index": fields,
            "conditions": full_conditions,
            "time_filter": ""
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
        eval_funcs = {
            'equals': lambda ev, cond: str(ev) == str(cond) if ev is not None else False,
            'contains': lambda ev, cond: str(cond) in str(ev) if ev is not None else False,
            'startswith': lambda ev, cond: str(ev).startswith(str(cond)) if ev is not None else False,
            'endswith': lambda ev, cond: str(ev).endswith(str(cond)) if ev is not None else False,
            're': lambda ev, cond: re.search(cond, str(ev)) is not None if ev is not None else False,
            'exists': lambda ev, cond: ev is not None,
            'base64': lambda ev, cond: str(ev) == cond if ev is not None else False,
        }
        op = modifiers[0] if modifiers else 'equals'
        func = eval_funcs.get(op, eval_funcs['equals'])
        if isinstance(condition_value, list) and 'all' in [m.lower() for m in modifiers]:
            return all(func(event_value, val) for val in condition_value)
        elif isinstance(condition_value, list):
            return any(func(event_value, val) for val in condition_value)
        return func(event_value, condition_value)

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
        search_results = {key: self.evaluate_search_identifier(siem_name, cond, event) for key, cond in detection.items() if key != "condition"}
        condition_str = detection.get("condition", "")
        for key, val in search_results.items():
            condition_str = re.sub(r'\b' + re.escape(key) + r'\b', str(val), condition_str)
        condition_str = re.sub(r'(1|all|none)\s+of\s+', '', condition_str)
        try:
            return eval(condition_str, {"__builtins__": {}}, {"True": True, "False": False})
        except Exception as e:
            logging.error(f"Error evaluating condition '{condition_str}': {e}")
            return False

    def test_rule(self, siem_name: str, sigma_rule: dict) -> None:
        test_log = sigma_rule.get('test_log')
        if not test_log:
            print("No test_log provided in the rule.")
            return
        print("=== Testing Rule ===")
        print("Raw Test Log:", test_log)
        try:
            event = yaml.safe_load(test_log)
            if not isinstance(event, dict):
                raise ValueError("test_log must be a JSON object")
        except Exception as e:
            print(f"Error parsing test_log: {e}")
            return
        print("\nParsed Event:", event)
        result = self.evaluate_detection(siem_name, sigma_rule.get('detection', {}), event)
        print("\nTest Result:", "PASSED" if result else "FAILED")

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
