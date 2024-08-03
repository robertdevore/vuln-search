import argparse
import os
import re
import csv
import signal
import sys
from datetime import datetime
from tqdm import tqdm
from concurrent.futures import ProcessPoolExecutor, as_completed

# Define pattern groups for Remote Code Execution detection
PATTERNS = {
    # General Patterns
    'general_exec_functions': [
        # Unsafe use of exec functions with user input
        (r'exec\s*\(\s*.*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
        (r'system\s*\(\s*.*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
        (r'shell_exec\s*\(\s*.*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
        (r'popen\s*\(\s*.*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
        (r'proc_open\s*\(\s*.*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
        (r'passthru\s*\(\s*.*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
        (r'pcntl_exec\s*\(\s*.*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
    ],
    'general_eval_functions': [
        # Unsafe use of eval and similar functions with user input
        (r'eval\s*\(\s*.*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
        (r'assert\s*\(\s*.*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
        (r'create_function\s*\(\s*.*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
    ],
    'general_file_inclusion': [
        # PHP file inclusion with user input
        (r'\binclude\b\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
        (r'\brequire\b\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
        (r'\binclude_once\b\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
        (r'\brequire_once\b\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
    ],
    'general_dynamic_function_calls': [
        # Dynamic function calls with user input
        (r'\$.*\(\s*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
    ],

    # WordPress Specific Patterns
    'wordpress_file_uploads': [
        # Insecure file uploads
        (r'move_uploaded_file\s*\(\s*\$_FILES\[.*\]\[\'tmp_name\'\].*', ''),
    ],
    'wordpress_plugin_theme_functions': [
        # Insecure plugin/theme function usage
        (r'do_action\s*\(\s*.*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
        (r'apply_filters\s*\(\s*.*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
    ],
    'wordpress_arbitrary_file_inclusion': [
        # Arbitrary file inclusion
        (r'include\s*\(\s*.*\$_SERVER\[\'DOCUMENT_ROOT\'\]\s*.\s*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
    ],

    # Laravel and Blade Specific Patterns
    'blade_insecure_syntax': [
        # Insecure Blade syntax
        (r'@php', ''),
        (r'\{!!.*!!\}', ''),
    ],
    'laravel_file_handling': [
        # Insecure file handling
        (r'Storage::put\s*\(\s*.*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
    ],
    'laravel_dynamic_route_definitions': [
        # Dynamic route definitions
        (r'Route::.*\(\s*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
    ],
    'laravel_unserialize_eval': [
        # Unsafe use of unserialize or eval
        (r'unserialize\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
        (r'eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\b', ''),
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
                        if not re.search(r'(escapeshellcmd|escapeshellarg|escapestring|addslashes|htmlentities|htmlspecialchars|filter_var|filter_input|sanitize_key|wp_unslash)\s*\(', line):
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
        csv_filename = os.path.join(results_dir, f"search-rce-results_{date_time_str}.csv")

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
