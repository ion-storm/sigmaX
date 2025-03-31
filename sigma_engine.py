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
    """Engine to convert Sigma rules into SIEM queries and test them."""
    def __init__(self, definition_file: str):
        self.definitions = self.load_yaml_file(definition_file)
        self.modifier_handlers = {
            # Simple passthrough modifiers
            **{mod: lambda siem, val, mods: val for mod in [
                'contains', 'startswith', 'endswith', 'equals', 'cased',
                'lt', 'lte', 'gt', 'gte', 'minute', 'hour', 'day', 'week', 'month', 'year'
            ]},
            # Special handlers
            "re": self._handle_regex,
            "base64": self._handle_base64,
            "base64offset": self._handle_base64offset,
            "expand": self._handle_expand,
            "windash": self._handle_windash,
            "cidr": self._handle_cidr,
            "fieldref": self._handle_fieldref,
            "not_contains": self._handle_not_contains,
            "not_equals": self._handle_not_equals,
            "exists": self._handle_exists,  # Added exists modifier
        }
        self.encoding_handlers = {
            "utf16le": lambda v: v.encode('utf-16le'), "utf16be": lambda v: v.encode('utf-16be'),
            "utf16": lambda v: b'\xFF\xFE' + v.encode('utf-16le'), "wide": lambda v: v.encode('utf-16le'),
        }
        self.siem_name = None

    def load_yaml_file(self, path: str) -> dict:
        """Load a YAML file safely."""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logging.error(f"Failed to load YAML file {path}: {e}")
            raise

    def map_field(self, siem_name: str, field: str) -> str:
        """Map Sigma field to SIEM-specific field."""
        siem = self.definitions['siems'].get(siem_name, {})
        mapped = siem.get('field_mappings', {}).get(field, field)
        if field not in siem.get('field_mappings', {}):
            logging.warning(f"Field '{field}' not mapped for {siem_name}")
        return mapped

    def escape_value(self, siem_name: str, value: str) -> str:
        """Escape special characters based on SIEM rules."""
        siem = self.definitions['siems'].get(siem_name, {})
        for char, repl in siem.get('escape_chars', {}).items():
            value = value.replace(char, repl)
        return value

    def format_value(self, siem_name: str, value: Union[str, List], modifiers: List[str] = None) -> Union[str, List]:
        """Format a value with modifiers for SIEM compatibility."""
        if 'cidr' in (modifiers or []) and isinstance(value, list):
            return self._handle_cidr(siem_name, value, modifiers)
        
        if isinstance(value, list):
            return [self.format_value(siem_name, v, modifiers) for v in value]
        
        value = str(value) if value is not None else ''
        
        if 'cidr' not in (modifiers or []):
            value = self.escape_value(siem_name, value)
        
        if value == 'null':
            return 'null'
        
        if modifiers:
            encoding = next((m for m in modifiers if m in self.encoding_handlers), None)
            for mod in modifiers:
                if mod in self.modifier_handlers and mod != 'all':
                    value = self.modifier_handlers[mod](siem_name, value, modifiers)
                elif mod not in {'all', 'i', 'm', 's', encoding}:
                    logging.warning(f"Unsupported modifier '{mod}' for {siem_name}")
            if encoding:
                value = base64.b64encode(self.encoding_handlers[encoding](value)).decode('ascii')
        
        siem = self.definitions['siems'][siem_name]
        fmt = siem.get('value_format', 'default')
        if fmt == 'always_quote' or (fmt == 'quote_if_space' and ' ' in value):
            return f'"{value}"'
        return value

    # Modifier Handlers
    def _handle_regex(self, siem_name: str, value: str, mods: List[str]) -> str:
        return value

    def _handle_base64(self, siem_name: str, value: str, mods: List[str]) -> str:
        return base64.b64encode(value.encode('ascii')).decode('ascii')

    def _handle_base64offset(self, siem_name: str, value: str, mods: List[str]) -> str:
        encoded = value.encode('ascii')
        variants = [base64.b64encode(b' ' * shift + encoded).decode('ascii') for shift in range(3)]
        return '|'.join(variants)

    def _handle_expand(self, siem_name: str, value: str, mods: List[str]) -> str:
        if value.startswith('%') and value.endswith('%'):
            logging.warning(f"Placeholder '{value}' not expanded (pipeline missing); using wildcard")
            return '*'
        return value

    def _handle_windash(self, siem_name: str, value: str, mods: List[str]) -> str:
        dashes = ['-', '/', '–', '—', '―']
        return '|'.join(value.replace('-', d) for d in dashes)

    def _handle_cidr(self, siem_name: str, value: str, mods: List[str]) -> str:
        siem = self.definitions['siems'].get(siem_name, {})
        if siem.get('cidr_supports_array', False) and isinstance(value, list):
            return '[' + ','.join(f'"{v}"' for v in value) + ']'
        return f'"{value}"'

    def _handle_fieldref(self, siem_name: str, value: str, mods: List[str]) -> str:
        return self.map_field(siem_name, value)

    def _handle_not_contains(self, siem_name: str, value: str, mods: List[str]) -> str:
        return value

    def _handle_not_equals(self, siem_name: str, value: str, mods: List[str]) -> str:
        return value

    def _handle_exists(self, siem_name: str, value: str, mods: List[str]) -> str:
        # Return the raw value ('true' or 'false') for SIEM-specific handling in _translate_dict
        return value

    def translate_search(self, siem_name: str, search_id: str, search: Union[dict, list]) -> str:
        siem = self.definitions['siems'].get(siem_name, {})
        ops = siem['operators']
        is_elastic = siem_name == "elasticsearch"
        joiner_any = siem.get('joiner_any_of', ' OR ' if not is_elastic else ', ')
        joiner_all = siem.get('joiner_all_of', ' AND ' if not is_elastic else ', ')
        
        if isinstance(search, list):
            conditions = [self._translate_dict(siem_name, item) if isinstance(item, dict) else [self.format_value(siem_name, item)]
                        for item in search]
            conditions = [c[0] if len(c) == 1 else joiner_any.join(c) for c in conditions]
            if len(conditions) == 1:
                result = conditions[0]
            else:
                result = f"({joiner_any.join(conditions)})"
        elif isinstance(search, dict):
            conditions = self._translate_dict(siem_name, search)
            if len(conditions) == 1:
                result = conditions[0]
            else:
                result = f"({joiner_all.join(conditions)})"
        else:
            raise ValueError(f"Invalid search structure for '{search_id}'")
        return f'{{"query_string": {{"query": "{result}"}}}}' if is_elastic else result

    def _translate_dict(self, siem_name: str, search: dict) -> List[str]:
        siem = self.definitions['siems'][siem_name]
        ops = siem['operators']
        windash_strategy = siem.get('windash_strategy', 'regex')
        conditions = []
        for field, value in search.items():
            base_field, *modifiers = field.split('|')
            mapped_field = self.map_field(siem_name, base_field)
            op = modifiers[0] if modifiers else 'equals'
            val = self.format_value(siem_name, value, modifiers)
            flags = ' CASE_SENSITIVE' if 'cased' in modifiers else ''
            if op == 'windash' and 'windash' in ops:
                windash_vals = val.split('|')
                tmpl = siem.get('windash_templates', {})
                if not tmpl:
                    logging.error(f"SIEM '{siem_name}' supports 'windash' but lacks 'windash_templates'")
                    raise ValueError(f"Missing 'windash_templates' for {siem_name}")
                condition = (tmpl['regex'].format(field=mapped_field, value=val) if windash_strategy == 'regex' else
                             tmpl['like'].format(conditions=' OR '.join(ops['contains'].format(field=mapped_field, value=v) for v in windash_vals)))
            elif op == 're' and 're' in ops:
                flags += ''.join(f' {f.upper()}' for f in ['multiline', 'dotall'] if f[0] in modifiers)
                condition = ops['re'].format(field=mapped_field, value=val, flags=flags.strip())
            elif op == 'cidr' and 'cidr' in ops:
                cidr_array = siem.get('cidr_supports_array', False)
                if isinstance(val, list) and not cidr_array:
                    logging.warning(f"SIEM '{siem_name}' does not support CIDR arrays; using first value {val[0]}")
                    val = val[0]
                condition = ops['cidr'].format(field=mapped_field, value=val if cidr_array else f'"{val}"')
            elif op == 'exists' and 'exists' in ops:
                # Handle exists modifier with true/false value
                condition = ops['exists'].format(field=mapped_field) if val.lower() == 'true' else f"NOT {ops['exists'].format(field=mapped_field)}"
            elif op not in ops:
                logging.warning(f"Operator '{op}' not supported for '{siem_name}', defaulting to 'equals'")
                condition = ops['equals'].format(field=mapped_field, value=val)
            elif isinstance(val, list):
                sub = [ops[op].format(field=mapped_field, value=v) for v in val]
                condition = siem['group_conditions']['all_of' if 'all' in modifiers else 'any_of'].format(conditions=' AND '.join(sub) if 'all' in modifiers else ' OR '.join(sub))
            elif op in {'lt', 'lte', 'gt', 'gte', 'minute', 'hour', 'day', 'week', 'month', 'year'} and op in ops:
                condition = ops[op].format(field=mapped_field, value=val)
            else:
                condition = ops[op].format(field=mapped_field, value=val, flags=flags)
            conditions.append(condition)
        return conditions

    def _parse_expr(self, tokens: List[str], siem_name: str, detection: dict, siem_def: dict, i: int = 0) -> Tuple[str, int]:
        parts = []
        is_elastic = siem_name == "elasticsearch"
        while i < len(tokens):
            tok = tokens[i].lower()
            if tok == '(':
                sub_expr, next_i = self._parse_expr(tokens, siem_name, detection, siem_def, i + 1)
                parts.append(f"({sub_expr})" if not is_elastic else sub_expr)
                i = next_i
            elif tok == ')':
                return " ".join(parts) if not is_elastic else f'"must": [{"".join(parts)}]', i + 1
            elif tok in ('and', 'or'):
                if tok == 'or' and siem_name == 'crowdstrike' and any('cidr(' in p for p in parts):
                    logging.error("Crowdstrike does not support 'OR' with cidr()")
                    raise ValueError("Invalid use of 'OR' with cidr in Crowdstrike")
                parts.append(tok.upper() if not is_elastic else f'"{tok}": [')
            elif tok == 'not' and i + 3 < len(tokens) and tokens[i + 1] == '1' and tokens[i + 2] == 'of':
                i += 3
                pattern = tokens[i] if i < len(tokens) else '*'
                matches = [sid for sid in detection if sid != 'condition' and re.match(pattern.replace('*', '.*'), sid)]
                if matches:
                    sub = [self.translate_search(siem_name, sid, detection[sid]) for sid in matches]
                    joiner = siem_def.get('joiner_any_of', ' OR ' if not is_elastic else ', ')
                    expr = siem_def['group_conditions']['any_of'].format(conditions=joiner.join(sub))
                    parts.append(f"NOT ({expr})" if not is_elastic else f'"must_not": [{{"query_string": {{"query": "{expr}"}}}}]')
                else:
                    parts.append('NOT *')
                i += 1
            elif tok == 'not':
                parts.append('NOT' if not is_elastic else '"must_not": [')
                i += 1
            elif tok in ('1', 'all') and i + 1 < len(tokens) and tokens[i + 1].lower() == 'of':
                op, i = tok, i + 2
                pattern = tokens[i] if i < len(tokens) else '*'
                matches = [sid for sid in detection if sid != 'condition' and re.match(pattern.replace('*', '.*'), sid)]
                if matches:
                    sub = [self.translate_search(siem_name, sid, detection[sid]) for sid in matches]
                    joiner = siem_def.get('joiner_all_of' if op == 'all' else 'joiner_any_of', ' AND ' if not is_elastic else ', ')
                    expr = siem_def['group_conditions']['all_of' if op == 'all' else 'any_of'].format(conditions=joiner.join(sub))
                    parts.append(expr if not is_elastic else f'{{"query_string": {{"query": "{expr}"}}}}')
                i += 1
            elif tok in detection and tok != 'condition':
                parts.append(self.translate_search(siem_name, tok, detection[tok]))
            else:
                parts.append(tokens[i])
            i += 1
        if len(parts) > 2 and parts[-2] == 'AND' and parts[-1].startswith('NOT'):
            return ' '.join(parts[:-2]) + ' ' + parts[-1], i
        return siem_def.get('joiner_all_of', ' AND ').join(parts) if not is_elastic else f'"must": [{"".join(parts)}]', i
    
    def parse_condition(self, siem_name: str, condition: str, detection: dict) -> str:
        siem = self.definitions['siems'][siem_name]
        parsed, _ = self._parse_expr(condition.split(), siem_name, detection, siem)
        return f'{{"bool": {{{parsed}}}}}' if siem_name == "elasticsearch" else parsed

    def generate_time_filter(self, siem_name: str, time_range: str) -> str:
        siem = self.definitions['siems'][siem_name]['time_filter']
        return f"{siem['keyword']}{siem['format'].get(time_range, siem['format']['default'])}"

    def generate_query(self, siem_name: str, sigma_rule: dict) -> str:
        self.siem_name = siem_name
        siem = self.definitions['siems'].get(siem_name, {})
        logsource = sigma_rule.get('logsource', {})
        index_key = '_'.join(filter(None, (logsource.get(k) for k in ('product', 'category', 'service'))))
        index = siem['index_map'].get(index_key) or siem['index_map'].get(logsource.get('category', 'default'), siem.get('default_index', ''))
        detection = sigma_rule['detection']
        condition = ' OR '.join(detection['condition']) if isinstance(detection['condition'], list) else detection['condition']
        logging.debug(f"generate_query: condition = {condition}")
        conditions = self.parse_condition(siem_name, condition, detection)
        logging.debug(f"generate_query: translated_conditions = {conditions}")
        time_filter = self.generate_time_filter(siem_name, sigma_rule.get('time_range', 'last_24_hours')).format(
            time_field=sigma_rule.get('time_field', siem.get('default_time_field', 'timestamp'))
        ) if siem.get('include_time_filter', False) else ''
        logging.debug(f"generate_query: time_filter = {time_filter}")
        full_conditions = conditions if not time_filter else siem.get('joiner_all_of', ' AND ').join([conditions, time_filter])
        logging.debug(f"generate_query: full_conditions = {full_conditions}")
        vars = {
            'columns': sigma_rule.get('columns', siem.get('default_columns', '*')),
            'index': index,
            'conditions': full_conditions,
            'time_filter': time_filter,
            'title': sigma_rule.get('title', ''),
            'description': sigma_rule.get('description', ''),
            'id': sigma_rule.get('id', ''),
            'tags': ' '.join(sigma_rule.get('tags', [])),
            **{k: ' '.join(map(str, v)) if isinstance(v, list) else str(v)
               for k, v in sigma_rule.items() if k not in ('detection', 'logsource', 'columns', 'time_field', 'time_range', 'test_log', 'tags')}
        }
        logging.debug(f"generate_query: template_vars = {vars}")
        try:
            return siem['query_template'].format(**vars)
        except KeyError as e:
            logging.error(f"Template variable missing for {siem_name}: {e}")
            raise

    def generate_query_from_file(self, siem_name: str, path: str) -> str:
        return self.generate_query(siem_name, self.load_yaml_file(path))

    def evaluate_field_condition(self, siem_name: str, field: str, value: Union[str, List], modifiers: List[str], event: dict) -> bool:
        mapped_field = self.map_field(siem_name, field)
        ev = event.get(mapped_field, event.get(field))
        val = value if isinstance(value, list) else str(value)
        op = modifiers[0] if modifiers else 'equals'
        evals = {
            'equals': lambda e, v: str(e) == str(v) if e is not None else False,
            'not_equals': lambda e, v: str(e) != str(v) if e is not None else False,
            'contains': lambda e, v: str(v) in str(e) if e is not None else False,
            'not_contains': lambda e, v: str(v) not in str(e) if e is not None else False,
            'startswith': lambda e, v: str(e).startswith(str(v)) if e is not None else False,
            'endswith': lambda e, v: str(e).endswith(str(v)) if e is not None else False,
            're': lambda e, v: bool(re.search(v, str(e), (re.I if 'i' in modifiers else 0) | (re.M if 'm' in modifiers else 0) | (re.S if 's' in modifiers else 0))) if e is not None else False,
            'exists': lambda e, v: (e is not None) == (str(v).lower() == 'true'),  # Updated for exists
            'base64': lambda e, v: str(e) == base64.b64encode(str(v).encode('ascii')).decode('ascii') if e is not None else False,
            'base64offset': lambda e, v: any(str(e) == v.split('|')[i] for i in range(3)) if e is not None else False,
            'windash': lambda e, v: any(re.search(re.escape(d), str(e)) for d in str(v).split('|')) if e is not None else False,
            'lt': lambda e, v: float(e) < float(v) if e is not None else False,
            'lte': lambda e, v: float(e) <= float(v) if e is not None else False,
            'gt': lambda e, v: float(e) > float(v) if e is not None else False,
            'gte': lambda e, v: float(e) >= float(v) if e is not None else False,
            'minute': lambda e, v: int(datetime.datetime.strptime(e, '%Y-%m-%dT%H:%M:%S.%fZ').minute) == int(v) if e else False,
            'hour': lambda e, v: int(datetime.datetime.strptime(e, '%Y-%m-%dT%H:%M:%S.%fZ').hour) == int(v) if e else False,
            'day': lambda e, v: int(datetime.datetime.strptime(e, '%Y-%m-%dT%H:%M:%S.%fZ').day) == int(v) if e else False,
            'week': lambda e, v: int(datetime.datetime.strptime(e, '%Y-%m-%dT%H:%M:%S.%fZ').isocalendar()[1]) == int(v) if e else False,
            'month': lambda e, v: int(datetime.datetime.strptime(e, '%Y-%m-%dT%H:%M:%S.%fZ').month) == int(v) if e else False,
            'year': lambda e, v: int(datetime.datetime.strptime(e, '%Y-%m-%dT%H:%M:%S.%fZ').year) == int(v) if e else False,
            'cidr': lambda e, v: any(ipaddress.ip_address(e) in ipaddress.ip_network(n, strict=False) for n in (v if isinstance(v, list) else [v])) if e and v else False,
            'fieldref': lambda e, v: str(e) == str(event.get(v)) if e is not None else False,
        }
        func = evals.get(op, evals['equals'])
        if 'cased' in modifiers and op in {'equals', 'not_equals', 'contains', 'not_contains', 'startswith', 'endswith'}:
            pass
        elif op in {'equals', 'not_equals', 'contains', 'not_contains', 'startswith', 'endswith'}:
            ev, val = str(ev).lower() if ev else None, [v.lower() for v in val] if isinstance(val, list) else str(val).lower()
        return all(func(ev, v) for v in val) if isinstance(val, list) and 'all' in modifiers else any(func(ev, v) for v in val) if isinstance(val, list) else func(ev, val)

    def evaluate_search_identifier(self, siem_name: str, search: Union[dict, list, str], event: dict) -> bool:
        if isinstance(search, dict):
            return all(self.evaluate_field_condition(siem_name, f.split('|')[0], v, f.split('|')[1:] if '|' in f else [], event) for f, v in search.items())
        elif isinstance(search, list):
            return any(self.evaluate_search_identifier(siem_name, item, event) for item in search)
        elif isinstance(search, str):
            return any(search in str(v) for v in event.values())
        return False

    def evaluate_detection(self, siem_name: str, detection: dict, event: dict) -> bool:
        results = {k: self.evaluate_search_identifier(siem_name, v, event) for k, v in detection.items() if k != "condition"}
        cond = detection.get("condition", "")
        tokens = cond.split()
        expr = []
        i = 0
        while i < len(tokens):
            tok = tokens[i].lower()
            if tok == 'not' and i + 1 < len(tokens):
                i += 1
                if tokens[i] in ('1', 'all') and i + 2 < len(tokens) and tokens[i + 1].lower() == 'of':
                    op, i = tokens[i], i + 2
                    pattern = tokens[i] if i < len(tokens) else '*'
                    matches = [k for k in results if re.match(pattern.replace('*', '.*'), k)]
                    expr.append(str(not any(results[k] for k in matches) if op == '1' else not all(results[k] for k in matches)))
                elif tokens[i] in results:
                    expr.append(str(not results[tokens[i]]))
                else:
                    expr.extend(['not', tokens[i]])
                i += 1
            elif tok in ('1', 'all') and i + 1 < len(tokens) and tokens[i + 1].lower() == 'of':
                op, i = tok, i + 2
                pattern = tokens[i] if i < len(tokens) else '*'
                matches = [k for k in results if re.match(pattern.replace('*', '.*'), k)]
                expr.append(str(any(results[k] for k in matches) if op == '1' else all(results[k] for k in matches)))
                i += 1
            elif tok in results:
                expr.append(str(results[tok]))
            else:
                expr.append(tok)
            i += 1
        try:
            return eval(' '.join(expr), {'__builtins__': {}}, {'True': True, 'False': False, 'and': lambda x, y: x and y, 'or': lambda x, y: x or y, 'not': lambda x: not x})
        except Exception as e:
            logging.error(f"Error evaluating '{cond}': {e}")
            return False

    def test_rule(self, siem_name: str, sigma_rule: dict) -> None:
        test_log = sigma_rule.get('test_log')
        if not test_log:
            print("No test_log provided in the rule.")
            return
        
        title = sigma_rule.get('title', 'Untitled')
        print(f"\n{'='*50}")
        print(f"Testing Rule: {title}")
        print(f"{'='*50}")
        
        try:
            event = yaml.safe_load(test_log)
            if not isinstance(event, dict):
                raise ValueError("test_log must be a JSON/YAML object")
        except Exception as e:
            print(f"❌ Error parsing test_log: {e}")
            return
        
        detection = sigma_rule.get('detection', {})
        results = {}
        
        for key, cond in detection.items():
            if key != 'condition':
                result = self.evaluate_search_identifier(siem_name, cond, event)
                results[key] = result
                print(f"\n🔍 Evaluating '{key}': {'✅' if result else '❌'}")
                if isinstance(cond, dict):
                    for f, v in cond.items():
                        mods = f.split('|')[1:] if '|' in f else []
                        fname = f.split('|')[0]
                        eval_result = self.evaluate_field_condition(siem_name, fname, v, mods, event)
                        print(f"  {'✅' if eval_result else '❌'} {f}: Expected: {v}, Got: {event.get(self.map_field(siem_name, fname), 'MISSING')}")
        
        final = self.evaluate_detection(siem_name, detection, event)
        print(f"\n📊 Final Condition: {detection.get('condition')}")
        print(f"📈 Evaluation Results: {results}")
        print(f"\n🏆 Test Result: {'✅ PASSED' if final else '❌ FAILED'}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate or test SIEM queries from Sigma rules.")
    parser.add_argument("siem", help="SIEM type (e.g., splunk, crowdstrike)")
    parser.add_argument("path", help="Path to Sigma rule file or directory")
    parser.add_argument("--test", action="store_true", help="Test rule against test_log")
    args = parser.parse_args()

    engine = UnifiedSIEMEngine("siem_definitions.yml")
    path = args.path
    if os.path.isdir(path):
        for file in [f for f in os.listdir(path) if f.endswith('.yml')]:
            full_path = os.path.join(path, file)
            try:
                rule = engine.load_yaml_file(full_path)
                print(f"--- {file} ---")
                engine.test_rule(args.siem, rule) if args.test else print(engine.generate_query(args.siem, rule))
            except Exception as e:
                print(f"Error processing {file}: {e}")
    elif os.path.isfile(path) and path.endswith('.yml'):
        try:
            rule = engine.load_yaml_file(path)
            engine.test_rule(args.siem, rule) if args.test else print(engine.generate_query(args.siem, rule))
        except Exception as e:
            print(f"Error processing {path}: {e}")
    else:
        print(f"Invalid path: {path}")
