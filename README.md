# sigmaX Engine

The sigmaX Engine is a unified SIEM query conversion and testing framework built around the Sigma rule format. It uses a definitions file to translate generic Sigma rules into SIEM-specific queries and to test those rules against sample log events.

## Features

- **Multi-SIEM Support:** Generate queries for multiple SIEM platforms (e.g., Splunk, CrowdStrike, Elasticsearch, Trino) using a single engine.
- **Definition-Driven:** All SIEM-specific settings (operator formats, index mappings, field mappings, etc.) are configured in an external YAML definitions file.
- **Sigma Rule Compliance:** Adheres to the standardized Sigma rule format, including metadata, detection logic, and test logs.
- **Built-in Testing:** Evaluate Sigma rules against realistic sample events (provided as JSON in the `test_log` field) to verify rule behavior.
- **Modular & Extensible:** Easily add support for new SIEM platforms or extend existing functionality through configuration changes rather than code modifications.

## Architecture

The sigmaX Engine is composed of three main components:

1. **Engine Core:**  
   - Parses Sigma rules and uses the definitions file to generate SIEM-specific queries.
   - Supports condition parsing, value formatting, and field mapping.

2. **Definitions File:**  
   - A YAML file containing SIEM-specific configurations such as operator templates, query templates, index mappings, field mappings, escape characters, and time filters.
   - Example SIEM entries include Splunk, CrowdStrike, Elasticsearch, and Trino.

3. **Sigma Rule Files:**  
   - YAML files that follow the Sigma rule schema. These files include metadata (title, id, author, etc.), logsource details, detection logic (with search identifiers and conditions), and optionally a `test_log` field for testing.

## Definitions File Format

Each SIEM platform in the definitions file contains:

- **name:** A human-readable name.
- **index_map:** Mapping of log source categories to SIEM indexes.
- **operators:** Templates for operators such as equals, contains, startswith, endswith, regex, and exists.
- **group_conditions:** Templates for grouping conditions (e.g., all_of, any_of, not).
- **time_filter:** Keyword and formats for time filtering.
- **query_template:** A template for the final query, with placeholders like `{index}`, `{conditions}`, and `{time_filter}`.
- **value_format:** Rules for value quoting.
- **escape_chars:** Characters to escape with their replacements.
- **field_mappings:** (Optional) Mappings for field names (e.g., mapping `CommandLine` to `cmdline`).

### Example (CrowdStrike)

```yaml
crowdstrike:
  name: "CrowdStrike LogScale Query Language"
  include_time_filter: false
  index_map:
    process_creation: "#repo=Falcon #event_simpleName=ProcessRollup2"
    firewall: "#repo=Falcon #event_simpleName=NetworkConnectIP4"
    default: "logs"
  operators:
    contains: "{field}=/{value}/i"
    startswith: "{field}=/^{value}/i"
    endswith: "{field}=/{value}$/i"
    re: "{field}=/{value}/i"
    equals: "{field}=\"{value}\""
    exists: "{field}=*"
  group_conditions:
    all_of: "({conditions})"
    any_of: "({conditions})"
    not: "NOT ({conditions})"
  time_filter:
    keyword: "@timestamp>="
    format:
      last_24_hours: "now()-24h"
      last_7_days: "now()-7d"
      last_30_days: "now()-30d"
      default: "now()-24h"
  query_template: "{index} {conditions} {time_filter}"
  value_format: "default"
  escape_chars:
    "\\" : "\\\\"
    "/" : "\\/"
    '"' : "\\\""
    ' ' : "\\s"
  field_mappings:
    CommandLine: "cmdline"
    Image: "image"
    ParentImage: "parent_image"
    OriginalFileName: "orig_file"
