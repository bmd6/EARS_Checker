import re
import argparse
import csv
import sys
from typing import List, Tuple, Dict, Optional

class EARSValidator:
    """
    A class to validate requirements against EARS syntax patterns.
    """

    def __init__(self):
        # Define regex patterns for each EARS pattern
        self.patterns = {
            'Ubiquitous': re.compile(
                r'^The\s+([A-Za-z0-9\s]+)\s+shall\s+(.+)\.$', re.IGNORECASE),
            'State Driven': re.compile(
                r'^While\s+(.+?),\s+the\s+([A-Za-z0-9\s]+)\s+shall\s+(.+)\.$', re.IGNORECASE),
            'Event Driven': re.compile(
                r'^When\s+(.+?),\s+the\s+([A-Za-z0-9\s]+)\s+shall\s+(.+)\.$', re.IGNORECASE),
            'Optional Feature': re.compile(
                r'^Where\s+(.+?),\s+the\s+([A-Za-z0-9\s]+)\s+shall\s+(.+)\.$', re.IGNORECASE),
            'Unwanted Behavior': re.compile(
                r'^If\s+(.+?),\s+then\s+the\s+([A-Za-z0-9\s]+)\s+shall\s+(.+)\.$', re.IGNORECASE),
            'Complex': re.compile(
                r'^(?:(?:While\s+.+?,\s+)?(?:When\s+.+?,\s+)?(?:Where\s+.+?,\s+)?(?:If\s+.+?,\s+then\s+)?the\s+[A-Za-z0-9\s]+\s+shall\s+.+\.)$', re.IGNORECASE)
        }

        # Define keywords for EARS patterns
        self.keywords = {
            'While': 'State Driven',
            'When': 'Event Driven',
            'Where': 'Optional Feature',
            'If': 'Unwanted Behavior',
            'Then': 'Unwanted Behavior',
            'shall': 'Response'
        }

    def validate(self, requirement: str) -> Tuple[bool, List[str], Optional[str]]:
        """
        Validate a single requirement.

        Returns:
            A tuple containing:
            - Compliance status (True/False)
            - List of EARS pattern names if compliant
            - Recommendation or matched pattern
        """
        requirement = requirement.strip()
        if not requirement:
            return False, [], 'Requirement is empty.'

        matched_patterns = []

        # Check for complex patterns first
        complex_match = self.patterns['Complex'].match(requirement)
        if complex_match:
            # Identify all patterns present in the complex requirement
            for keyword, pattern_name in self.keywords.items():
                if re.search(r'\b' + re.escape(keyword) + r'\b', requirement, re.IGNORECASE):
                    if pattern_name not in matched_patterns:
                        matched_patterns.append(pattern_name)
            # Ensure that at least two patterns are present for it to be considered complex
            if len(matched_patterns) >= 2:
                return True, ['Complex'] + matched_patterns, 'Compliant with Complex patterns: ' + ', '.join(matched_patterns)
        
        # Check for single patterns
        for pattern_name, pattern_regex in self.patterns.items():
            if pattern_name == 'Complex':
                continue  # Already handled
            if pattern_regex.match(requirement):
                matched_patterns.append(pattern_name)
        
        if matched_patterns:
            return True, matched_patterns, 'Compliant with ' + ', '.join(matched_patterns) + ' pattern(s).'
        
        # If no patterns matched, determine why it's non-compliant
        recommendation = self.recommend_modification(requirement)
        return False, [], recommendation

    def recommend_modification(self, requirement: str) -> str:
        """
        Provide recommendations to make the requirement EARS compliant.
        """
        # Check for 'shall' keyword
        if not re.search(r'\bshall\b', requirement, re.IGNORECASE):
            return ("Add the keyword 'shall' to specify the system response. Example:\n"
                    "  'When <trigger>, the <system name> shall <system response>.'")

        # Check for presence of EARS keywords
        present_keywords = [kw for kw in self.keywords if re.search(r'\b' + re.escape(kw) + r'\b', requirement, re.IGNORECASE)]
        if not present_keywords:
            return ("Consider using a EARS pattern by including one of the keywords: "
                    "While, When, Where, If. For example:\n"
                    "  'The <system name> shall <system response>.' for Ubiquitous requirements.")

        # Check clause order
        clauses_order = ['While', 'When', 'Where', 'If', 'Then', 'shall']
        lower_req = requirement.lower()
        indices = {kw: lower_req.find(kw.lower()) for kw in clauses_order if re.search(r'\b' + re.escape(kw) + r'\b', requirement, re.IGNORECASE)}
        sorted_indices = sorted(indices.items(), key=lambda x: x[1])
        sorted_keywords = [item[0] for item in sorted_indices]
        correct_order = sorted(sorted_keywords, key=lambda x: clauses_order.index(x))
        if sorted_keywords != correct_order:
            return ("Ensure that clauses are in the correct order: While, When, Where, If, Then, shall.")

        return "The requirement structure does not match any EARS pattern. Please revise accordingly."

def read_requirements(file_path: str) -> List[str]:
    """
    Read requirements from a given file.

    Args:
        file_path: Path to the input file.

    Returns:
        A list of requirements as strings.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            requirements = file.readlines()
        return [req.strip() for req in requirements if req.strip()]
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.", file=sys.stderr)
        sys.exit(1)
    except IOError as e:
        print(f"IOError while reading the file '{file_path}': {e}", file=sys.stderr)
        sys.exit(1)

def generate_report(requirements: List[str], validator: EARSValidator) -> Dict:
    """
    Generate a report based on the validation of requirements.

    Args:
        requirements: List of requirement strings.
        validator: An instance of EARSValidator.

    Returns:
        A dictionary containing the assessment results.
    """
    report = {
        'requirements': [],
        'compliant_count': 0,
        'non_compliant_count': 0,
        'patterns': {}
    }

    for req in requirements:
        compliant, patterns, info = validator.validate(req)
        report['requirements'].append({
            'requirement': req,
            'compliant': compliant,
            'patterns': patterns if compliant else [],
            'info': info
        })
        if compliant:
            report['compliant_count'] += 1
            for pattern in patterns:
                if pattern not in ['Complex']:
                    report['patterns'][pattern] = report['patterns'].get(pattern, 0) + 1
            if 'Complex' in patterns:
                # Count complex as a separate category
                report['patterns']['Complex'] = report['patterns'].get('Complex', 0) + 1
        else:
            report['non_compliant_count'] += 1

    return report

def output_results(report: Dict, output_format: str, output_file: str = None):
    """
    Output the assessment results in the desired format.

    Args:
        report: The assessment report dictionary.
        output_format: Desired output format ('terminal', 'txt', 'csv', 'md', 'org').
        output_file: Path to the output file if not terminal.
    """
    if output_format == 'terminal':
        print_report_terminal(report)
    elif output_format in ['txt', 'csv', 'md', 'org']:
        if not output_file:
            print("Error: Output file path must be provided for non-terminal outputs.", file=sys.stderr)
            sys.exit(1)
        if output_format == 'txt':
            write_txt(report, output_file)
        elif output_format == 'csv':
            write_csv(report, output_file)
        elif output_format == 'md':
            write_md(report, output_file)
        elif output_format == 'org':
            write_org(report, output_file)
    else:
        print(f"Error: Unsupported output format '{output_format}'.", file=sys.stderr)
        sys.exit(1)

def print_report_terminal(report: Dict):
    """
    Print the report to the terminal.
    """
    print("=== EARS Syntax Compliance Report ===\n")
    for idx, req in enumerate(report['requirements'], 1):
        status = "✅ Compliant" if req['compliant'] else "❌ Non-compliant"
        print(f"Requirement {idx}: {req['requirement']}")
        print(f"Status: {status}")
        if req['compliant']:
            if 'Complex' in req['patterns']:
                patterns_display = ', '.join([p for p in req['patterns'] if p != 'Complex'])
                print(f"EARS Pattern: Complex ({patterns_display})")
            else:
                patterns_display = ', '.join(req['patterns'])
                print(f"EARS Pattern: {patterns_display}")
        else:
            print(f"Recommendation: {req['info']}")
        print("-" * 50)
    
    print("\n=== Summary ===")
    print(f"Total Requirements: {len(report['requirements'])}")
    print(f"EARS Compliant: {report['compliant_count']}")
    print(f"Non-compliant: {report['non_compliant_count']}")
    print("\nRequirements per EARS Pattern:")
    for pattern, count in report['patterns'].items():
        print(f"  {pattern}: {count}")

def write_txt(report: Dict, file_path: str):
    """
    Write the report to a TXT file.
    """
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("=== EARS Syntax Compliance Report ===\n\n")
            for idx, req in enumerate(report['requirements'], 1):
                status = "✅ Compliant" if req['compliant'] else "❌ Non-compliant"
                f.write(f"Requirement {idx}: {req['requirement']}\n")
                f.write(f"Status: {status}\n")
                if req['compliant']:
                    if 'Complex' in req['patterns']:
                        patterns_display = ', '.join([p for p in req['patterns'] if p != 'Complex'])
                        f.write(f"EARS Pattern: Complex ({patterns_display})\n")
                    else:
                        patterns_display = ', '.join(req['patterns'])
                        f.write(f"EARS Pattern: {patterns_display}\n")
                else:
                    f.write(f"Recommendation: {req['info']}\n")
                f.write("-" * 50 + "\n")
            
            f.write("\n=== Summary ===\n")
            f.write(f"Total Requirements: {len(report['requirements'])}\n")
            f.write(f"EARS Compliant: {report['compliant_count']}\n")
            f.write(f"Non-compliant: {report['non_compliant_count']}\n")
            f.write("\nRequirements per EARS Pattern:\n")
            for pattern, count in report['patterns'].items():
                f.write(f"  {pattern}: {count}\n")
        print(f"Report successfully written to '{file_path}'.")
    except IOError as e:
        print(f"IOError while writing to the file '{file_path}': {e}", file=sys.stderr)
        sys.exit(1)

def write_csv(report: Dict, file_path: str):
    """
    Write the report to a CSV file.
    """
    try:
        with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Requirement', 'Compliant', 'Patterns', 'Info']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for req in report['requirements']:
                writer.writerow({
                    'Requirement': req['requirement'],
                    'Compliant': req['compliant'],
                    'Patterns': ', '.join(req['patterns']) if req['compliant'] else '',
                    'Info': req['info']
                })
            
            # Write summary
            writer.writerow({})
            writer.writerow({'Requirement': 'Summary'})
            writer.writerow({'Requirement': 'Total Requirements', 'Compliant': len(report['requirements'])})
            writer.writerow({'Requirement': 'EARS Compliant', 'Compliant': report['compliant_count']})
            writer.writerow({'Requirement': 'Non-compliant', 'Compliant': report['non_compliant_count']})
            writer.writerow({})
            writer.writerow({'Requirement': 'Requirements per EARS Pattern'})
            for pattern, count in report['patterns'].items():
                writer.writerow({'Requirement': pattern, 'Compliant': count})
        print(f"Report successfully written to '{file_path}'.")
    except IOError as e:
        print(f"IOError while writing to the file '{file_path}': {e}", file=sys.stderr)
        sys.exit(1)

def write_md(report: Dict, file_path: str):
    """
    Write the report to a Markdown file.
    """
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("# EARS Syntax Compliance Report\n\n")
            for idx, req in enumerate(report['requirements'], 1):
                status = "✅ Compliant" if req['compliant'] else "❌ Non-compliant"
                f.write(f"## Requirement {idx}\n")
                f.write(f"**Text:** {req['requirement']}\n\n")
                f.write(f"**Status:** {status}\n\n")
                if req['compliant']:
                    if 'Complex' in req['patterns']:
                        patterns_display = ', '.join([p for p in req['patterns'] if p != 'Complex'])
                        f.write(f"**EARS Pattern:** Complex ({patterns_display})\n\n")
                    else:
                        patterns_display = ', '.join(req['patterns'])
                        f.write(f"**EARS Pattern:** {patterns_display}\n\n")
                else:
                    f.write(f"**Recommendation:** {req['info']}\n\n")
                f.write("---\n\n")
            
            # Summary
            f.write("## Summary\n")
            f.write(f"- **Total Requirements:** {len(report['requirements'])}\n")
            f.write(f"- **EARS Compliant:** {report['compliant_count']}\n")
            f.write(f"- **Non-compliant:** {report['non_compliant_count']}\n\n")
            f.write("### Requirements per EARS Pattern\n")
            for pattern, count in report['patterns'].items():
                f.write(f"- **{pattern}:** {count}\n")
        print(f"Report successfully written to '{file_path}'.")
    except IOError as e:
        print(f"IOError while writing to the file '{file_path}': {e}", file=sys.stderr)
        sys.exit(1)

def write_org(report: Dict, file_path: str):
    """
    Write the report to an Org-mode file.
    """
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("* EARS Syntax Compliance Report\n\n")
            for idx, req in enumerate(report['requirements'], 1):
                status = "Compliant" if req['compliant'] else "Non-compliant"
                f.write(f"** Requirement {idx}\n")
                f.write(f"   - Text: {req['requirement']}\n")
                f.write(f"   - Status: {status}\n")
                if req['compliant']:
                    if 'Complex' in req['patterns']:
                        patterns_display = ', '.join([p for p in req['patterns'] if p != 'Complex'])
                        f.write(f"   - EARS Pattern: Complex ({patterns_display})\n")
                    else:
                        patterns_display = ', '.join(req['patterns'])
                        f.write(f"   - EARS Pattern: {patterns_display}\n")
                else:
                    f.write(f"   - Recommendation: {req['info']}\n")
            
            # Summary
            f.write("\n* Summary\n")
            f.write(f"- Total Requirements: {len(report['requirements'])}\n")
            f.write(f"- EARS Compliant: {report['compliant_count']}\n")
            f.write(f"- Non-compliant: {report['non_compliant_count']}\n")
            f.write("- Requirements per EARS Pattern:\n")
            for pattern, count in report['patterns'].items():
                f.write(f"  - {pattern}: {count}\n")
        print(f"Report successfully written to '{file_path}'.")
    except IOError as e:
        print(f"IOError while writing to the file '{file_path}': {e}", file=sys.stderr)
        sys.exit(1)

def parse_arguments():
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(description='Assess requirements for EARS syntax compliance.')
    parser.add_argument('input_file', help='Path to the input file containing requirements.')
    parser.add_argument('-o', '--output', help='Path to the output file.', default=None)
    parser.add_argument('-f', '--format', 
                        choices=['terminal', 'txt', 'csv', 'md', 'org'], 
                        default='terminal', 
                        help='Output format: terminal, txt, csv, md, org. Default is terminal.')
    return parser.parse_args()

def main():
    args = parse_arguments()
    requirements = read_requirements(args.input_file)
    validator = EARSValidator()
    report = generate_report(requirements, validator)
    output_results(report, args.format, args.output)

if __name__ == '__main__':
    main()
