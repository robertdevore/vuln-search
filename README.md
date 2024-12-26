# Vulnerability Scanner

## Overview

This repository contains a suite of scripts designed to identify various security vulnerabilities in PHP applications.

The tools are tailored to detect common security issues such as SQL Injection, Cross-Site Scripting, Cross-Site Request Forgery, and Remote Code Execution vulnerabilities.

The scanner aims to automate the detection of these issues, providing a starting point for securing web applications.

## Tools

### Bash Script

- **`vulnsearch.sh`**: This script orchestrates the execution of the individual Python tools, providing a unified interface to scan for multiple vulnerabilities across a specified directory of PHP files.

### Python Scripts

- **`searchXSS.py`**: Detects potential XSS vulnerabilities by scanning for insecure handling of user inputs in web contexts.
- **`searchCSRF.py`**: Identifies potential CSRF vulnerabilities by looking for insecure or missing request validation mechanisms.
- **`searchRCE.py`**: Searches for RCE vulnerabilities, particularly focusing on dangerous function usage that could allow for arbitrary code execution.
- **`searchSQLi.py`**: Detects SQL Injection vulnerabilities by identifying insecure SQL query constructions, especially those involving unsanitized user inputs.
- **`searchIDOR.py`**: Detects potential IDOR (Insecure Direct Object Reference) vulnerabilities by identifying patterns where access to resources, files, or data objects is improperly controlled based on user input.

## Usage

### Default Behavior

If no `--tools` option is provided, the script will execute all Python scripts found in the `/scripts/` directory. Similarly, if the `--patterns` option is not specified, the default pattern group all will be used.

### Using --tools

The `--tools` option allows you to specify which scripts to run by their index. The index corresponds to the position of the script in the list of found Python scripts.

**Example**

```
./vulnsearch.sh --directory /path/to/your/php/files --tools 1,3,5
```

In this example, the script will execute the first, third, and fifth Python scripts found in the `/scripts/` directory.

### Using --patterns

The `--patterns` option allows you to specify a particular pattern group to use during the scan. This can be useful for targeting specific types of vulnerabilities.

**Example**

```
./vulnsearch.sh --directory /path/to/your/php/files --patterns sql_injection_patterns
```

In this example, the script will use the `sql_injection_patterns` group for the scan.

### Output

The results are saved in CSV format in the results directory, with filenames indicating the date and time of the scan. The total execution time is displayed in the terminal after the scan completes.

### Available patterns

**1. Cross-Site Scripting (XSS) Patterns**

*   direct_output
*   html_attributes
*   javascript_context
*   event_handlers
*   url_redirection
*   html_tags
*   javascript_functions
*   reflected_stored_xss
*   csp_bypasses
*   json_handling
*   miscellaneous

**2. Cross-Site Request Forgery (CSRF) Patterns**

*   general_csrf_patterns
*   wordpress_specific_patterns
*   framework_specific_patterns
*   ruby_on_rails_patterns
*   javascript_csrf_patterns
*   common_csrf_mechanisms
*   blade_template_patterns

**3. Remote Code Execution (RCE) Patterns**

*   general_exec_functions
*   general_eval_functions
*   general_file_inclusion
*   general_dynamic_function_calls
*   wordpress_file_uploads
*   wordpress_plugin_theme_functions
*   wordpress_arbitrary_file_inclusion
*   blade_insecure_syntax
*   laravel_file_handling
*   laravel_dynamic_route_definitions
*   laravel_unserialize_eval

**4. SQL Injection (SQLi) Patterns**

*   direct_sql_queries
*   sql_injection_patterns
*   direct_database_calls
*   additional_patterns
*   unsafe_php_functions

**5. IDOR Patterns**

*   idor_parametrized_queries
*   idor_file_access
*   idor_url_parameters

These names represent the categories of patterns that the scripts are configured to detect, and they guide the scanning process for potential vulnerabilities.

## Contributing

Contributions are welcome! If you have suggestions for new patterns, improvements to the scripts, or bug fixes, please open an issue or submit a pull request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is intended for educational and testing purposes only. The author is not responsible for any misuse or damage caused by the use of this tool.