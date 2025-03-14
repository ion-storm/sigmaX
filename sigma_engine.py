import yaml
import re
import logging
import os
import argparse
from typing import Dict, List, Union, Tuple

logging.basicConfig(level=logging.INFO)

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
        }

    def load_yaml_file(self, path: str) -> dict:
        with open(path, 'r') as file:
            return yaml.safe_load(file)

    def map_field(self, siem_name: str, field: str) -> str:
        """Return the mapped field name if defined."""
        siem_def = self.definitions['siems'].get(siem_name)
        if not siem_def:
            raise ValueError(f"SIEM '{siem_name}' not found in definitions.")
        mappings = siem_def.get('field_mappings', {})
        return mappings.get(field, field)

    def escape_value(self, siem_name: str, value: str) -> str:
        siem_def = self.definitions['siems'].get(siem_name)
        if not siem_def:
            raise ValueError(f"SIEM '{siem_name}' not found in definitions.")
        escape_chars = siem_def.get('escape_chars', {})
        for char, replacement in escape_chars.items():
            value = value.replace(char, replacement)
        return value

    def format_value(self, siem_name: str, value: Union[str, List[str]], modifiers: List[str] = None) -> Union[str, List[str]]:
        if isinstance(value, list):
            return [self.format_value(siem_name, v, modifiers) for v in value]
        value = self.escape_value(siem_name, value)
        if value == 'null':
            return 'null'
        if modifiers:
            for modifier in modifiers:
                if modifier in self.modifier_handlers:
                    value = self.modifier_handlers[modifier](siem_name, value)
        siem_def = self.definitions['siems'][siem_name]
        formatting_rule = siem_def.get('value_format', 'default')
        if formatting_rule == 'quote_if_space' and ' ' in value:
            return f'"{value}"'
        elif formatting_rule == 'always_quote':
            return f'"{value}"'
        return value

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

    def translate_search(self, siem_name: str, search_id: str, search: Union[dict, list]) -> str:
        siem_def = self.definitions['siems'].get(siem_name)
        operators = siem_def['operators']
        if isinstance(search, list):
            conditions = []
            for item in search:
                if isinstance(item, dict):
                    conditions.extend(self._translate_dict(siem_name, item))
                else:
                    conditions.append(self.format_value(siem_name, item))
            joiner = siem_def.get('joiner_any_of', ' OR ')
            return siem_def['group_conditions']['any_of'].format(conditions=joiner.join(conditions))
        elif isinstance(search, dict):
            conditions = self._translate_dict(siem_name, search)
            joiner = siem_def.get('joiner_all_of', ' AND ')
            return siem_def['group_conditions']['all_of'].format(conditions=joiner.join(conditions))
        raise ValueError(f"Invalid search structure for '{search_id}'")

    def _translate_dict(self, siem_name: str, search: dict) -> List[str]:
        siem_def = self.definitions['siems'][siem_name]
        operators = siem_def['operators']
        conditions = []
        for field, value in search.items():
            # Split field from modifiers and map the field name.
            base_field = field.split('|')[0]
            mapped_field = self.map_field(siem_name, base_field)
            modifiers = []
            if '|' in field:
                _, *modifiers = field.split('|')
            operator_key = modifiers[0] if modifiers else 'equals'
            if operator_key not in operators:
                raise ValueError(f"Operator '{operator_key}' not supported for '{siem_name}'")
            formatted_value = self.format_value(siem_name, value, modifiers)
            if isinstance(formatted_value, list):
                sub_conditions = [operators[operator_key].format(field=mapped_field, value=v) for v in formatted_value]
                joiner = siem_def.get('joiner_any_of', ' OR ')
                if len(modifiers) > 1 and any(m.lower() == 'all' for m in modifiers[1:]):
                    joiner = siem_def.get('joiner_all_of', ' AND ')
                condition = siem_def['group_conditions']['any_of'].format(conditions=joiner.join(sub_conditions))
            else:
                condition = operators[operator_key].format(field=mapped_field, value=formatted_value)
            conditions.append(condition)
        return conditions

    # New recursive parser for condition expression (unchanged)
    def _parse_expr(self, tokens: List[str], siem_name: str, detection: dict, siem_def: dict, i: int = 0) -> Tuple[str, int]:
        expr_parts = []
        while i < len(tokens):
            token = tokens[i]
            low_token = token.lower()
            if token == '(':
                sub_expr, i = self._parse_expr(tokens, siem_name, detection, siem_def, i + 1)
                expr_parts.append(f"({sub_expr})")
            elif token == ')':
                return " ".join(expr_parts), i + 1
            elif low_token in ('and', 'or'):
                expr_parts.append(token.upper())
                i += 1
            elif low_token == 'not':
                expr_parts.append("NOT")
                i += 1
            elif low_token in ('1', 'all', 'none') and (i + 1 < len(tokens) and tokens[i + 1].lower() == 'of'):
                op = low_token
                i += 2
                if i < len(tokens):
                    pattern = tokens[i]
                    i += 1
                    matches = [
                        sid for sid in detection
                        if re.match(pattern.replace('*', '.*'), sid) and sid != 'condition'
                    ]
                    if matches:
                        sub_conditions = [
                            self.translate_search(siem_name, sid, detection[sid])
                            for sid in matches
                        ]
                        if op == '1':
                            joiner = siem_def.get('joiner_any_of', ' OR ')
                            group_expr = siem_def['group_conditions']['any_of'].format(conditions=joiner.join(sub_conditions))
                        elif op == 'all':
                            joiner = siem_def.get('joiner_all_of', ' AND ')
                            group_expr = siem_def['group_conditions']['all_of'].format(conditions=joiner.join(sub_conditions))
                        elif op == 'none':
                            joiner = siem_def.get('joiner_any_of', ' OR ')
                            group_expr = f"NOT {siem_def['group_conditions']['any_of'].format(conditions=joiner.join(sub_conditions))}"
                        expr_parts.append(group_expr)
                    else:
                        expr_parts.append("")
            else:
                if token in detection and token != 'condition':
                    expr_parts.append(self.translate_search(siem_name, token, detection[token]))
                else:
                    expr_parts.append(token)
                i += 1
        return " ".join(expr_parts), i

    def parse_condition(self, siem_name: str, condition: str, detection: dict) -> str:
        siem_def = self.definitions['siems'][siem_name]
        tokens = condition.split()
        parsed_expr, _ = self._parse_expr(tokens, siem_name, detection, siem_def, 0)
        return parsed_expr

    def generate_time_filter(self, siem_name: str, time_range: str) -> str:
        siem_def = self.definitions['siems'][siem_name]
        time_filter_def = siem_def['time_filter']
        keyword = time_filter_def['keyword']
        value = time_filter_def['format'].get(time_range, time_filter_def['format']['default'])
        return f"{keyword}{value}"

    def generate_query(self, siem_name: str, sigma_rule: dict) -> str:
        siem_def = self.definitions['siems'].get(siem_name)
        if not siem_def:
            raise ValueError(f"SIEM '{siem_name}' not found in definitions.")
        logsource = sigma_rule.get('logsource', {})
        fields = siem_def['index_map'].get(
            logsource.get('category', 'default'),
            siem_def.get('default_index', '')
        )
        detection = sigma_rule['detection']
        condition = detection['condition']
        if isinstance(condition, list):
            condition = ' OR '.join(condition)
        translated_conditions = self.parse_condition(siem_name, condition, detection)
        
        include_time_filter = siem_def.get('include_time_filter', False)
        if include_time_filter:
            time_range = sigma_rule.get('time_range', 'last_24_hours')
            time_filter = self.generate_time_filter(siem_name, time_range)
        else:
            time_filter = ''
        
        query_template = siem_def['query_template']
        template_vars = {
            "fields": fields,
            "conditions": translated_conditions,
            "time_filter": time_filter
        }
        if "{index}" in query_template:
            template_vars["index"] = fields
        query = query_template.format(**template_vars)
        return query

    def generate_query_from_file(self, siem_name: str, sigma_rule_file: str) -> str:
        sigma_rule = self.load_yaml_file(sigma_rule_file)
        return self.generate_query(siem_name, sigma_rule)

    # --- New Evaluation Functions for Testing Against a JSON Log Event ---

    def evaluate_field_condition(self, siem_name: str, field: str, condition_value: Union[str, List[str]], modifiers: List[str], event: dict) -> bool:
        # Map the field name and attempt to fetch the value from the event.
        mapped_field = self.map_field(siem_name, field)
        event_value = event.get(mapped_field)
        # Fallback: if not found, try the original field name.
        if event_value is None:
            event_value = event.get(field)
        eval_funcs = {
            'equals': lambda ev, cond: str(ev).lower() == str(cond).lower() if ev is not None else False,
            'contains': lambda ev, cond: str(cond).lower() in str(ev).lower() if ev is not None else False,
            'startswith': lambda ev, cond: str(ev).lower().startswith(str(cond).lower()) if ev is not None else False,
            'endswith': lambda ev, cond: str(ev).lower().endswith(str(cond).lower()) if ev is not None else False,
            're': lambda ev, cond: re.search(cond, str(ev), re.IGNORECASE) is not None if ev is not None else False,
            'exists': lambda ev, cond: ev is not None
        }
        op = modifiers[0] if modifiers else 'equals'
        func = eval_funcs.get(op, eval_funcs['equals'])
        if isinstance(condition_value, list):
            return any(func(event_value, val) for val in condition_value)
        else:
            return func(event_value, condition_value)

    def evaluate_search_identifier(self, siem_name: str, search: Union[dict, list, str], event: dict) -> bool:
        if isinstance(search, dict):
            results = []
            for field, value in search.items():
                modifiers = []
                base_field = field.split('|')[0]
                if '|' in field:
                    _, *modifiers = field.split('|')
                results.append(self.evaluate_field_condition(siem_name, base_field, value, modifiers, event))
            return all(results)
        elif isinstance(search, list):
            return any(self.evaluate_search_identifier(siem_name, item, event) for item in search)
        elif isinstance(search, str):
            return any(search.lower() in str(val).lower() for val in event.values())
        else:
            return False

    def evaluate_detection(self, siem_name: str, detection: dict, event: dict) -> bool:
        search_results = {}
        for key, cond in detection.items():
            if key == "condition":
                continue
            search_results[key] = self.evaluate_search_identifier(siem_name, cond, event)
        condition_str = detection.get("condition", "")
        # Replace each search identifier token with its boolean value.
        for key, val in search_results.items():
            condition_str = re.sub(r'\b' + re.escape(key) + r'\b', str(val), condition_str)
        # Remove tokens "1 of", "all of", "none of"
        condition_str = condition_str.replace("1 of", "").replace("all of", "").replace("none of", "")
        try:
            return eval(condition_str)
        except Exception as e:
            print("Error evaluating condition:", condition_str, e)
            return False

    def test_rule(self, siem_name: str, sigma_rule: dict) -> None:
        """Test the rule against a JSON test log event provided in the rule."""
        test_log = sigma_rule.get('test_log')
        if not test_log:
            print("No test_log provided in the rule.")
            return

        print("=== Testing Rule ===")
        print("Raw Test Log:")
        print(test_log)
        try:
            # Parse the test_log as JSON (yaml.safe_load can handle JSON)
            event = yaml.safe_load(test_log)
        except Exception as e:
            print("Error parsing test_log as JSON:", e)
            return
        print("\nParsed Event:")
        print(event)
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
                        print(f"{args.siem} - {rule_file}: {query}")
                except Exception as e:
                    print(f"Error processing {rule_file}: {e}")
    elif os.path.isfile(args.path) and args.path.endswith('.yml'):
        try:
            if args.test:
                sigma_rule = engine.load_yaml_file(args.path)
                engine.test_rule(args.siem, sigma_rule)
            else:
                query = engine.generate_query_from_file(args.siem, args.path)
                print(f"{args.siem} - {args.path}:\n{query}")
        except Exception as e:
            print(f"Error processing {args.path}: {e}")
    else:
        print(f"Invalid path: {args.path}. Must be a .yml file or a directory.")
