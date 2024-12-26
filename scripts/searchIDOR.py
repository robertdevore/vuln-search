import argparse
import os
import re
import csv
from datetime import datetime
from tqdm import tqdm
from concurrent.futures import ProcessPoolExecutor, as_completed

# Define pattern groups
PATTERNS = {
    'idor_parametrized_queries': [
        # Access to objects directly based on user input without authorization
        (r'\bSELECT\s+.*\bFROM\s+.*\bWHERE\s+.*\b(id|user_id|account_id)\b\s*=\s*\$_(GET|POST|REQUEST)\b', ''),
        (r'\bDELETE\s+FROM\s+.*\bWHERE\s+.*\b(id|user_id|account_id)\b\s*=\s*\$_(GET|POST|REQUEST)\b', ''),
    ],
    'idor_file_access': [
        # File access directly based on user input
        (r'\bfile_get_contents\s*\(\s*\$_(GET|POST|REQUEST)\b', ''),
        (r'\binclude\s*\(\s*\$_(GET|POST|REQUEST)\b', ''),
        (r'\brequire\s*\(\s*\$_(GET|POST|REQUEST)\b', ''),
        (r'\binclude_once\s*\(\s*\$_(GET|POST|REQUEST)\b', ''),
        (r'\brequire_once\s*\(\s*\$_(GET|POST|REQUEST)\b', ''),
    ],
    'idor_url_parameters': [
        # URL parameters directly used to reference objects
        (r'\bheader\s*\(\s*[\'"]Location:\s*.*\?id=\s*\$_(GET|POST|REQUEST)\b', ''),
    ],
}

def parse_arguments():
    parser = argparse.ArgumentParser(description="Search for IDOR vulnerabilities in PHP files.")
    parser.add_argument(
        '--directory',
        type=str,
        required=True,
        help="The directory to scan for PHP files. This argument is required."
    )
    parser.add_argument(
        '--patterns',
        choices=list(PATTERNS.keys()) + ['all'],
        default='all',
        help="Select the pattern group to use. Defaults to 'all'."
    )
    return parser.parse_args()

def search_php_files(directory):
    php_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".php"):
                php_files.append(os.path.join(root, file))
    return php_files

def process_pattern_group(pattern_group, php_files):
    found_data = []
    match_count = 0

    for pattern, _ in pattern_group:
        for file in php_files:
            with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                matches = re.findall(pattern, content)
                for match in matches:
                    found_data.append((file, match))
                    match_count += 1

    return found_data, match_count

def save_to_csv(data, filename):
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["File", "Match"])
        for row in data:
            writer.writerow(row)

def main():
    args = parse_arguments()

    try:
        target_directory = args.directory
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

        results_dir = "results"
        if not os.path.exists(results_dir):
            os.makedirs(results_dir)

        date_time_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        csv_filename = os.path.join(results_dir, f"search-idor-results_{date_time_str}.csv")

        save_to_csv(found_data, csv_filename)

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
