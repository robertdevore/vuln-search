import argparse
import os
import re
import csv
import signal
import sys
from datetime import datetime
from tqdm import tqdm
from concurrent.futures import ProcessPoolExecutor, as_completed

# Define pattern groups for CSRF
PATTERNS = {
    'general_csrf_patterns': [
        # Forms using POST method without CSRF token
        (r'<form[^>]*method=["\']post["\'][^>]*>', ''),
        # Forms that do not include a hidden CSRF token field
        (r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']token["\'][^>]*>', ''),
        # Generic PHP checks (missing these is an issue)
        (r'\$_POST\b.*=.*\b\$_GET\b', ''),  # Assigning $_GET values to $_POST
        (r'if\s*\(\s*isset\s*\(\s*\$_POST\b.*\)\s*\)', r'!\$_SESSION\[\'csrf_token\'\]'),
    ],
    'wordpress_specific_patterns': [
        # Missing nonce verification
        (r'(if\s*\(\s*isset\s*\(\s*\$_POST\b.*\))', r'!check_admin_referer\('),
        (r'(if\s*\(\s*isset\s*\(\s*\$_POST\b.*\))', r'!wp_verify_nonce\('),
        # Forms without wp_nonce_field
        (r'<form[^>]*method=["\']post["\'][^>]*>', r'wp_nonce_field\('),
        # AJAX actions without check_ajax_referer
        (r'add_action\(\s*[\'"][^\'"]*_ajax_[^\'"]*[\'"]\s*,', r'check_ajax_referer\('),
        (r'add_action\(\s*[\'"][^\'"]*_ajax_nopriv_[^\'"]*[\'"]\s*,', r'check_ajax_referer\('),
        # Unsanitized $_POST, $_GET, and $_REQUEST
        (r'\$_POST\[\s*\'[^\']+\'\s*\]', r'(sanitize_text_field|esc_attr|esc_html|wp_kses_post)\s*\('),
        (r'\$_GET\[\s*\'[^\']+\'\s*\]', r'(sanitize_text_field|esc_attr|esc_html|wp_kses_post)\s*\('),
        (r'\$_REQUEST\[\s*\'[^\']+\'\s*\]', r'(sanitize_text_field|esc_attr|esc_html|wp_kses_post)\s*\('),
        # Custom REST API endpoints without proper permissions
        (r'register_rest_route\(', r'\bpermission_callback\b\s*=>\s*__return_true'),
        (r'register_rest_route\(', r'\bpermission_callback\b\s*=>\s*__return_false'),
    ],
    'framework_specific_patterns': [
        # Laravel CSRF token checks
        (r'@csrf', ''),
        (r'\$request->input\(', r'\$request->session()->token\('),
        # Symfony CSRF token validation
        (r'\$request->get\(', r'\$request->request->get\('),
        (r'\$form->handleRequest\(', r'\$form->isSubmitted\(\) && \$form->isValid\('),
        # Yii2 CSRF token validation
        (r'\\Yii::\$app->request->post\(', r'\\Yii::\$app->request->validateCsrfToken\('),
    ],
    'ruby_on_rails_patterns': [
        # Rails CSRF token field checks
        (r'<%= csrf_meta_tags %>', ''),
        (r'<%= form_tag', r'<%= csrf_meta_tag %>'),
    ],
    'javascript_csrf_patterns': [
        # JavaScript CSRF token usage
        (r'fetch\(', r'headers:\s*{[^}]*"X-CSRF-Token"'),
        (r'XMLHttpRequest\(', r'X-CSRF-Token'),
        (r'\.ajax\(', r'headers:\s*{[^}]*"X-CSRF-Token"'),
    ],
    'common_csrf_mechanisms': [
        # Checking for presence of common CSRF prevention mechanisms
        (r'\$_SESSION\[\'csrf_token\'\]', ''),  # Usage of session-based CSRF tokens
        (r'\$_COOKIE\[\'csrf_token\'\]', ''),   # Usage of cookie-based CSRF tokens
    ],
    'blade_template_patterns': [
        # Forms using POST method without CSRF token
        (r'<form[^>]*method=["\']post["\'][^>]*>', r'@csrf'),
        # Custom CSRF token field
        (r'<input[^>]*name=["\']_token["\'][^>]*>', ''),
        # Direct use of {{ $variable }} without escaping
        (r'\{{\s*\$[a-zA-Z_]\w*\s*\}\}', r''),
        # Direct use of {!! $variable !!} (indicates unescaped output)
        (r'\{{!!\s*\$[a-zA-Z_]\w*\s*!!\}\}', r''),
        # JavaScript AJAX requests with CSRF token
        (r'headers:\s*{\s*["\']X-CSRF-TOKEN["\']\s*:\s*\$\(\'meta\[name="csrf-token"\]\'\).attr\(\'content\'\)', ''),
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
                    if pattern.search(line) and (not sub_pattern or not sub_pattern.search(line)):
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
        csv_filename = os.path.join(results_dir, f"search-csrf-results_{date_time_str}.csv")

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
