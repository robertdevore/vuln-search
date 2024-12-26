import argparse
import os
import re
import csv
import signal
import sys
from datetime import datetime
from tqdm import tqdm
from concurrent.futures import ProcessPoolExecutor, as_completed

# Define pattern groups
PATTERNS = {
    'direct_output': [
        # Direct Use of Unescaped Data in Output
        (r'echo\s+.*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
        (r'print\s+.*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
        (r'\$_(POST|GET|REQUEST|COOKIE)\s*;', ''),
    ],
    'html_attributes': [
        # Direct Use of Unescaped Data in HTML Attributes
        (r'\bvalue\s*=\s*[\'"].*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
        (r'\bdata-\w+\s*=\s*[\'"].*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
    ],
    'javascript_context': [
        # JavaScript Context
        (r'<script\b[^>]*>.*\$_(POST|GET|REQUEST|COOKIE)\b.*</script>', ''),
        (r'location\.href\s*=\s*.*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
        (r'document\.write\s*\(.*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
        (r'innerHTML\s*=\s*.*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
    ],
    'event_handlers': [
        # Dynamic Event Handlers
        (r'on(click|load|mouseover|etc)\s*=\s*[\'"].*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
    ],
    'url_redirection': [
        # URL Redirection
        (r'header\s*\(\s*[\'"]Location:\s*.*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
        (r'window\.location\s*=\s*.*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
    ],
    'html_tags': [
        # Untrusted Data in HTML Tags
        (r'<iframe\b[^>]*src\s*=\s*[\'"].*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
        (r'<img\b[^>]*src\s*=\s*[\'"].*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
    ],
    'javascript_functions': [
        # JavaScript Functions
        (r'eval\s*\(.*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
        (r'setTimeout\s*\(.*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
        (r'setInterval\s*\(.*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
    ],
    'reflected_stored_xss': [
        # Reflected and Stored XSS
        (r'echo\s*\$_(POST|GET|REQUEST|COOKIE)\s*;', ''),
        (r'print\s*\$_(POST|GET|REQUEST|COOKIE)\s*;', ''),
    ],
    'csp_bypasses': [
        # Content Security Policy Bypasses
        (r'<style\b[^>]*>.*\$_(POST|GET|REQUEST|COOKIE)\b.*</style>', ''),
    ],
    'json_handling': [
        # Handling of JSON Data
        (r'json_encode\s*\(.*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
        (r'json_decode\s*\(.*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
    ],
    'miscellaneous': [
        # Miscellaneous Patterns
        (r'<a\b[^>]*href\s*=\s*[\'"].*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
        (r'<object\b[^>]*data\s*=\s*[\'"].*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
    ],
    'wordpress': [
        # SQL Injection Vulnerabilities
        (r'\$wpdb->query\s*\(.*[^\)]\s*\)', ''),
        (r'mysql_query\s*\(.*[^\)]\s*\)', ''),
        (r'mysqli_query\s*\(.*[^\)]\s*\)', ''),
        # File Inclusion Vulnerabilities
        (r'include\s*\(.*\$_(POST|GET|REQUEST|COOKIE)\b.*\)', ''),
        (r'require\s*\(.*\$_(POST|GET|REQUEST|COOKIE)\b.*\)', ''),
        (r'include_once\s*\(.*\$_(POST|GET|REQUEST|COOKIE)\b.*\)', ''),
        (r'require_once\s*\(.*\$_(POST|GET|REQUEST|COOKIE)\b.*\)', ''),
        # Insecure Function Usage
        (r'eval\s*\(.*\)', ''),
        (r'exec\s*\(.*\)', ''),
        (r'system\s*\(.*\)', ''),
        (r'passthru\s*\(.*\)', ''),
        (r'shell_exec\s*\(.*\)', ''),
        # Unsafe Usage of `unserialize`
        (r'unserialize\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\b.*\)', ''),
    ],
    'blade': [
        # Unsafe Output Rendering
        (r'\{!!.*!!\}', ''),
        # Direct Access to User Input
        (r'\{\{\s*\$_(POST|GET|REQUEST|COOKIE)\b.*\}\}', ''),
        # Usage of Dangerous Blade Directives
        (r'@php', ''),
        (r'@inject\s*\(.*\)', ''),
    ],
}

def signal_handler(signal, frame):
    """
    Handles the signal interrupt (e.g., Ctrl+C) and saves the data before exiting.
    """
    print("\nInterrupted! Exiting...")
    sys.exit(0)

def search_php_files(root_dir):
    """
    Recursively searches for PHP files in the given directory and its subdirectories.
    """
    php_files = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename.endswith('.php'):
                file_path = os.path.join(dirpath, filename)
                php_files.append(file_path)
    return php_files

def search_in_file(file_path, patterns):
    """
    Searches for specific patterns in a given file.
    """
    matches = []
    compiled_patterns = [(re.compile(pattern), re.compile(sub_pattern)) for pattern, sub_pattern in patterns]
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                for pattern, sub_pattern in compiled_patterns:
                    if pattern.search(line) and sub_pattern.search(line):
                        if not re.search(r'(sanitize_text_field|esc_html|esc_attr|esc_sql|addslashes|untrailingslashit|wp_unslash|rest_sanitize_boolean|absint|sanitize_conditions|sanitize_url|stripslashes|sanitize_key)\s*\(', line):
                            matches.append(line.strip())
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
    return file_path, matches

def save_to_csv(data, csv_file):
    """
    Saves the found data to a CSV file.
    """
    with open(csv_file, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["File Path", "Matching Line"])
        for file_path, lines in data:
            for line in lines:
                writer.writerow([file_path, line])

def parse_arguments():
    """
    Parses command-line arguments.
    """
    parser = argparse.ArgumentParser(description="Search for patterns in PHP files.")
    parser.add_argument(
        '--patterns',
        choices=list(PATTERNS.keys()) + ['all'],
        default='all',
        help="Select the pattern group to use. Defaults to 'all'."
    )
    parser.add_argument(
        '--directory',
        type=str,
        required=True,
        help="The directory to scan for PHP files. This argument is required."
    )
    return parser.parse_args()

def process_pattern_group(pattern_group, php_files):
    """
    Processes a pattern group for all PHP files and counts matches.
    """
    pattern_counts = {pattern: 0 for pattern, _ in pattern_group}  # Initialize pattern counts
    found_data = []

    with ProcessPoolExecutor() as executor:
        futures = {executor.submit(search_in_file, php_file, pattern_group): php_file for php_file in php_files}

        for future in tqdm(as_completed(futures), total=len(futures), desc="Processing files", unit="file"):
            try:
                file_path, results = future.result()
                if results:
                    found_data.append((file_path, results))
                    # Count matches for each pattern
                    for pattern, _ in pattern_group:
                        if any(re.search(pattern, line) for line in results):
                            pattern_counts[pattern] += len(results)
            except Exception as e:
                print(f"Error processing file: {e}")

    # Aggregate counts by pattern group
    total_count = sum(pattern_counts.values())
    
    return found_data, total_count

def main():
    # Set up signal handler for graceful exit
    signal.signal(signal.SIGINT, signal_handler)

    # Parse arguments
    args = parse_arguments()

    try:
        # Get the target directory from arguments
        target_directory = args.directory

        # Find all PHP files in the target directory and subdirectories
        php_files = search_php_files(target_directory)

        found_data = []
        total_matches = {}

        if args.patterns == 'all':
            for group_name, pattern_group in PATTERNS.items():
                print(f"\nProcessing pattern group: {group_name}")
                data, count = process_pattern_group(pattern_group, php_files)
                found_data.extend(data)
                total_matches[group_name] = count
        else:
            selected_patterns = PATTERNS[args.patterns]
            data, count = process_pattern_group(selected_patterns, php_files)
            found_data.extend(data)
            total_matches[args.patterns] = count

        # Generate the results directory path
        results_dir = "results"
        # Create the results directory if it does not exist
        if not os.path.exists(results_dir):
            os.makedirs(results_dir)

        # Generate the CSV file name with the current date and time
        date_time_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        csv_filename = os.path.join(results_dir, f"search-xss-results_{date_time_str}.csv")

        # Save the results to a CSV file
        save_to_csv(found_data, csv_filename)

        # Print summary information
        print(f"\nResults have been saved to {csv_filename}")
        print("\nPotential Matches:\n")

        any_matches = False
        for group_name, count in total_matches.items():
            if count > 0:
                print(f"Pattern group '{group_name}' - {count} matches")
                any_matches = True
        
        if not any_matches:
            print("No matches found for any patterns.")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
