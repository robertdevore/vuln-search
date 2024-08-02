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
    'direct_sql_queries': [
        (r'->get_results\(', r'\$_POST|\$_GET'),
        (r'update_option\(', r'\$_POST|\$_GET'),
        (r'move_uploaded_file\(', r'\$_FILES|\$_POST'),
        (r'^echo\s+[^();]*\b\$_POST\b[^();]*;$', ''),
        (r'^echo\s+[^();]*\b\$_GET\b[^();]*;$', ''),
        (r'wp_delete_post\(', r'\$_POST|\$_GET'),
        (r'wp_add_post\(', r'\$_POST|\$_GET'),
        (r'\$_SESSION\s*\[\s*\'[^\']+\'\s*\]\s*=\s*\$_POST\s*;', ''),
        (r'\$_SESSION\s*\[\s*\'[^\']+\'\s*\]\s*=\s*\$_GET\s*;', ''),
        (r'\bfile_get_contents\(\s*[\'"][^\'"]*[\'"]\s*\)\s*;', ''),
    ],
    'sql_injection_patterns': [
        (r'\bSELECT\b.*\bFROM\b.*\bWHERE\b.*\$_POST\b', ''),
        (r'\bUPDATE\b.*\bSET\b.*\bWHERE\b.*\$_POST\b', ''),
        (r'\bDELETE\b.*\bFROM\b.*\bWHERE\b.*\$_POST\b', ''),
        (r'\bSELECT\b.*\bFROM\b.*\bWHERE\b.*\$_GET\b', ''),
        (r'\bUPDATE\b.*\bSET\b.*\bWHERE\b.*\$_GET\b', ''),
        (r'\bDELETE\b.*\bFROM\b.*\bWHERE\b.*\$_GET\b', ''),
        # New patterns
        (r'\bINSERT\b.*\bINTO\b.*\$_POST\b', ''),
        (r'\bINSERT\b.*\bINTO\b.*\$_GET\b', ''),
        (r'\bSELECT\b.*\bFROM\b.*\bWHERE\b.*\$_REQUEST\b', ''),
        (r'\bUPDATE\b.*\bSET\b.*\bWHERE\b.*\$_REQUEST\b', ''),
        (r'\bDELETE\b.*\bFROM\b.*\bWHERE\b.*\$_REQUEST\b', ''),
        (r'\bINSERT\b.*\bINTO\b.*\$_REQUEST\b', ''),
        (r'\bSELECT\b.*\bFROM\b.*\bWHERE\b.*\$_COOKIE\b', ''),
        (r'\bUPDATE\b.*\bSET\b.*\bWHERE\b.*\$_COOKIE\b', ''),
        (r'\bDELETE\b.*\bFROM\b.*\bWHERE\b.*\$_COOKIE\b', ''),
        (r'\bINSERT\b.*\bINTO\b.*\$_COOKIE\b', ''),
    ],
    'direct_database_calls': [
        (r'\$wpdb->query\(\s*.*\$_POST\b', ''),
        (r'\$wpdb->prepare\(\s*.*\$_POST\b', ''),
        (r'\$wpdb->query\(\s*.*\$_GET\b', ''),
        (r'\$wpdb->prepare\(\s*.*\$_GET\b', ''),
        (r'\bmysql_query\(\s*.*\$_POST\b', ''),
        (r'\bmysqli_query\(\s*.*\$_POST\b', ''),
        (r'\bmysql_query\(\s*.*\$_GET\b', ''),
        (r'\bmysqli_query\(\s*.*\$_GET\b', ''),
        (r'\baddslashes\(\s*\$_POST\b', ''),
        (r'\baddslashes\(\s*\$_GET\b', ''),
        (r'\bmysql_real_escape_string\(\s*\$_POST\b', ''),
        (r'\bmysqli_real_escape_string\(\s*\$_POST\b', ''),
        (r'\bmysql_real_escape_string\(\s*\$_GET\b', ''),
        (r'\bmysqli_real_escape_string\(\s*\$_GET\b', ''),
        # New patterns
        (r'\$wpdb->query\(\s*.*\$_REQUEST\b', ''),
        (r'\$wpdb->prepare\(\s*.*\$_REQUEST\b', ''),
        (r'\bmysql_query\(\s*.*\$_REQUEST\b', ''),
        (r'\bmysqli_query\(\s*.*\$_REQUEST\b', ''),
        (r'\bmysql_real_escape_string\(\s*\$_REQUEST\b', ''),
        (r'\bmysqli_real_escape_string\(\s*\$_REQUEST\b', ''),
        (r'\$wpdb->query\(\s*.*\$_COOKIE\b', ''),
        (r'\$wpdb->prepare\(\s*.*\$_COOKIE\b', ''),
        (r'\bmysql_query\(\s*.*\$_COOKIE\b', ''),
        (r'\bmysqli_query\(\s*.*\$_COOKIE\b', ''),
        (r'\bmysql_real_escape_string\(\s*\$_COOKIE\b', ''),
        (r'\bmysqli_real_escape_string\(\s*\$_COOKIE\b', ''),
    ],
    'additional_patterns': [
        (r'add_filter\(\s*[\'"][^\'"]*[\'"]\s*,\s*\$_POST\b', ''),
        (r'add_action\(\s*[\'"][^\'"]*[\'"]\s*,\s*\$_POST\b', ''),
        # New patterns
        (r'add_filter\(\s*[\'"][^\'"]*[\'"]\s*,\s*\$_GET\b', ''),
        (r'add_action\(\s*[\'"][^\'"]*[\'"]\s*,\s*\$_GET\b', ''),
        (r'add_filter\(\s*[\'"][^\'"]*[\'"]\s*,\s*\$_REQUEST\b', ''),
        (r'add_action\(\s*[\'"][^\'"]*[\'"]\s*,\s*\$_REQUEST\b', ''),
        (r'add_filter\(\s*[\'"][^\'"]*[\'"]\s*,\s*\$_COOKIE\b', ''),
        (r'add_action\(\s*[\'"][^\'"]*[\'"]\s*,\s*\$_COOKIE\b', ''),
    ],
    'unsafe_php_functions': [
        (r'exec\(\s*.*\$_POST\b', ''),
        (r'exec\(\s*.*\$_GET\b', ''),
        (r'exec\(\s*.*\$_REQUEST\b', ''),
        (r'exec\(\s*.*\$_COOKIE\b', ''),
        (r'system\(\s*.*\$_POST\b', ''),
        (r'system\(\s*.*\$_GET\b', ''),
        (r'system\(\s*.*\$_REQUEST\b', ''),
        (r'system\(\s*.*\$_COOKIE\b', ''),
        (r'shell_exec\(\s*.*\$_POST\b', ''),
        (r'shell_exec\(\s*.*\$_GET\b', ''),
        (r'shell_exec\(\s*.*\$_REQUEST\b', ''),
        (r'shell_exec\(\s*.*\$_COOKIE\b', ''),
        (r'popen\(\s*.*\$_POST\b', ''),
        (r'popen\(\s*.*\$_GET\b', ''),
        (r'popen\(\s*.*\$_REQUEST\b', ''),
        (r'popen\(\s*.*\$_COOKIE\b', ''),
        (r'proc_open\(\s*.*\$_POST\b', ''),
        (r'proc_open\(\s*.*\$_GET\b', ''),
        (r'proc_open\(\s*.*\$_REQUEST\b', ''),
        (r'proc_open\(\s*.*\$_COOKIE\b', ''),
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
                        if not re.search(r'(sanitize_text_field|esc_html|esc_attr|esc_sql|addslashes|untrailingslashit|wp_unslash|rest_sanitize_boolean|absint|sanitize_conditions|sanitize_url|stripslashes|wp_kses|wp_kses_post|sanitize_text_or_array_field|$wpdb->prepare)\s*\(', line):
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
        help='Select the pattern group to use.',
        required=True
    )
    parser.add_argument(
        '--directory',
        type=str,
        default=os.getcwd(),
        help='The directory to scan for PHP files. Defaults to the current working directory.'
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
        # Get the target directory from arguments or use the current directory
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
        csv_filename = os.path.join(results_dir, f"search-sqli-results_{date_time_str}.csv")

        # Save the results to a CSV file
        save_to_csv(found_data, csv_filename)

        # Print summary information
        print(f"\nResults have been saved to {csv_filename}")
        print("\nSearch Summary:")
        print(f"Total files searched: {len(php_files)}")
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
