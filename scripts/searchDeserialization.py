import argparse
import os
import re
import csv
import signal
import sys
from datetime import datetime
from tqdm import tqdm
from concurrent.futures import ProcessPoolExecutor, as_completed

# Define patterns for insecure deserialization
PATTERNS = {
    'unserialize_patterns': [
        # Direct unserialize() usage with user input
        (r'unserialize\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SERVER|SESSION)\b', ''),
        (r'unserialize\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*', ''),  # Untrusted variable in unserialize()
        # Unserialize usage in sensitive functions
        (r'\bcall_user_func\s*\(\s*unserialize\s*\(.*\)\)', ''),
        (r'\bcall_user_func_array\s*\(\s*unserialize\s*\(.*\)\)', ''),
        (r'\bset_error_handler\s*\(\s*unserialize\s*\(.*\)\)', ''),
        (r'\brestore_error_handler\s*\(\s*unserialize\s*\(.*\)\)', ''),
    ],
    'php_object_injection': [
        # Suspicious object injection patterns
        (r'O:\d+:".*":\d+:{.*}', ''),  # PHP serialized object
        (r'C:\d+:".*":\d+:{.*}', ''),  # PHP serialized closure
        # Patterns indicating unserialization vulnerabilities
        (r'unserialize\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SERVER|SESSION|REQUEST_URI)\b', ''),
        (r'unserialize\s*\(\s*\$_FILES\b.*\)', ''),
    ],
    'json_deserialization': [
        # JSON deserialization without proper validation
        (r'json_decode\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SERVER|SESSION)\b', ''),
        (r'json_decode\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*,\s*true\s*\)', ''),  # Parsing untrusted data
        (r'json_decode\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*,\s*false\s*\)', ''),  # Parsing JSON as object
        # Using decoded JSON in unsafe contexts
        (r'\$decoded_data\s*=\s*json_decode\(.*\);\s*eval\s*\(\$decoded_data\b.*\)', ''),
        (r'\$decoded_data\s*=\s*json_decode\(.*\);\s*exec\s*\(\$decoded_data\b.*\)', ''),
    ],
    'serialize_patterns': [
        # Potential dangerous use of serialize()
        (r'serialize\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SERVER|SESSION)\b', ''),
        (r'serialize\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*', ''),  # Untrusted variable in serialize()
        # Serialize patterns in file handling
        (r'file_put_contents\s*\(\s*[\'"].*\.ser[\'"],\s*serialize\s*\(.*\)\)', ''),  # Serialized data in files
        (r'fwrite\s*\(\s*.*,\s*serialize\s*\(.*\)\)', ''),
    ],
    'object_instantiation': [
        # Potentially unsafe object instantiation
        (r'new\s*[A-Za-z_][A-Za-z0-9_]*\s*\(\s*unserialize\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SESSION)\b', ''),
    ],
    'data_exposure': [
        # Exposure of serialized or unserialized data
        (r'echo\s*serialize\s*\(.*\);', ''),
        (r'print\s*serialize\s*\(.*\);', ''),
        (r'var_dump\s*\(.*serialize\s*\(.*\)\);', ''),
        (r'die\s*\(.*serialize\s*\(.*\)\);', ''),
        (r'echo\s*json_encode\s*\(.*unserialize\s*\(.*\)\);', ''),
    ],
    'php_magic_methods': [
        # Usage of PHP magic methods with serialized input
        (r'__wakeup', ''),  # Deserialization entry point
        (r'__destruct', ''),  # Dangerous behavior on object destruction
        (r'__toString', ''),  # Dangerous type juggling
        (r'__call', ''),  # Runtime method invocation
        (r'__invoke', ''),  # Callable object pattern
    ],
    'generic_deserialization': [
        # Deserialization in non-PHP contexts
        (r'pickle.loads\(', ''),  # Python deserialization
        (r'java.io.ObjectInputStream', ''),  # Java deserialization
    ],
}

def signal_handler(signal, frame):
    print("\nInterrupted! Exiting...")
    sys.exit(0)

def search_php_files(root_dir):
    php_files = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename.endswith('.php'):
                php_files.append(os.path.join(dirpath, filename))
    return php_files

def search_in_file(file_path, patterns):
    matches = []
    compiled_patterns = [re.compile(pattern) for pattern, _ in patterns]
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                for pattern in compiled_patterns:
                    if pattern.search(line):
                        if not re.search(r'(addslashes|escapeshellarg|filter_var|json_last_error|htmlentities|htmlspecialchars|is_serialized)\s*\(', line):
                            matches.append(line.strip())
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
    return file_path, matches

def save_to_csv(data, csv_file):
    with open(csv_file, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["File Path", "Matching Line"])
        for file_path, lines in data:
            for line in lines:
                writer.writerow([file_path, line])

def parse_arguments():
    parser = argparse.ArgumentParser(description="Search for insecure deserialization patterns in PHP files.")
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
    found_data = []
    with ProcessPoolExecutor() as executor:
        futures = {executor.submit(search_in_file, php_file, pattern_group): php_file for php_file in php_files}
        for future in tqdm(as_completed(futures), total=len(futures), desc="Processing files", unit="file"):
            try:
                file_path, results = future.result()
                if results:
                    found_data.append((file_path, results))
            except Exception as e:
                print(f"Error processing file: {e}")
    return found_data

def main():
    signal.signal(signal.SIGINT, signal_handler)
    args = parse_arguments()
    try:
        target_directory = args.directory
        php_files = search_php_files(target_directory)

        found_data = []

        if args.patterns == 'all':
            for group_name, pattern_group in PATTERNS.items():
                print(f"\nProcessing pattern group: {group_name}")
                found_data.extend(process_pattern_group(pattern_group, php_files))
        else:
            selected_patterns = PATTERNS[args.patterns]
            found_data.extend(process_pattern_group(selected_patterns, php_files))

        results_dir = "results"
        if not os.path.exists(results_dir):
            os.makedirs(results_dir)

        date_time_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        csv_filename = os.path.join(results_dir, f"search-deserialization-results_{date_time_str}.csv")

        save_to_csv(found_data, csv_filename)

        print(f"\nResults have been saved to {csv_filename}")
        print("\nPotential Matches:\n")
        if found_data:
            print(f"Found {len(found_data)} potential matches.")
        else:
            print("No matches found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
