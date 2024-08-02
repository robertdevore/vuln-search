# Vulnerability Search Tool

This project provides a set of scripts for detecting vulnerabilities in PHP code, including SQL Injection, Remote Code Execution, XSS, and other security flaws. The scripts can be run through a bash script `vulnsearch.sh` to analyze PHP files in a specified directory and save the results in CSV format.

## Features

- **Pattern Matching**: Detects various patterns indicative of vulnerabilities such as SQL Injection, Remote Code Execution, and XSS.
- **Multi-threaded Execution**: Uses concurrent processing to speed up the scanning of files.
- **Customizable Patterns**: Supports adding new pattern groups for different types of vulnerability detection.
- **Results Storage**: Saves results in a `/results/` folder in CSV format.

## Requirements

- Python 3.x
- Bash (for running `vulnsearch.sh`)

## Installation

1. Clone the repository or download the scripts.
2. Ensure Python 3.x is installed on your system.
3. Install required Python packages: `pip install -r requirements.txt`

Make sure to create and activate a virtual environment before installing packages.

## Usage

### Running the Bash Script

To run the vulnsearch.sh script, use the following command:

`./vulnsearch.sh --patterns PATTERN [--tools INDEXES] [--directory DIRECTORY]`

*   `--patterns PATTERN`: The pattern group to use (e.g., sql_injection_patterns, remote_code_execution, xss_patterns).
*   `--tools INDEXES`: (Optional) Comma-separated list of tool indices to run, based on their order in the scripts directory.
*   `--directory DIRECTORY`: (Optional) Directory to scan for PHP files. Defaults to the current working directory if not specified.

### Example

`./vulnsearch.sh --patterns xss_patterns --tools 2 --directory "/path/to/folder/"`

This command runs the second tool script in the `/scripts/` directory, scanning for `xss_patterns` in the specified directory.

## Output

The results will be saved in the /results/ directory in CSV format. The filename includes a timestamp to ensure uniqueness and provide context for when the scan was performed.

### Adding New Patterns

To add new patterns for detection:

* Open the corresponding Python script for the vulnerability type.
* Modify the PATTERNS dictionary to include your new patterns.
* Ensure the pattern group is listed correctly in the script's argument parsing section.

## Contributing

Contributions are welcome! Please follow these steps:

* Fork the repository.
* Create a new branch (git checkout -b feature-branch).
* Make your changes and commit them (git commit -am 'Add new feature').
* Push to the branch (git push origin feature-branch).
* Create a new Pull Request.

## License

This project is licensed under the GPLv3 License. See the LICENSE file for details.

## Disclaimer

This tool is provided as-is for educational purposes. The authors are not responsible for any misuse or damage caused by using this tool.
