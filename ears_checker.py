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

def print_ears_info():
    """
    Print information about EARS syntax, including types and expected patterns.
    """
    info = """
=== EARS Syntax Information ===

**What is EARS?**

The Easy Approach to Requirements Syntax (EARS) is a mechanism to gently constrain textual requirements. EARS patterns provide structured guidance that enable authors to write high-quality textual requirements. EARS uses a small set of keywords to denote different clauses of a requirement, following temporal logic. The syntax closely matches common English usage, making it intuitive.

**EARS Patterns:**

1. **Ubiquitous Requirements**
   - **Pattern:**
     ```
     The <system name> shall <system response>.
     ```
   - **Examples:**
     - The kitchen system shall have an input hatch.
     - The control system shall prevent engine overspeed.
     - The installer software shall be available in Greek.

2. **Event-Driven Requirements**
   - **Pattern:**
     ```
     When <optional preconditions> <trigger>, the <system> shall <system response>.
     ```
   - **Examples:**
     - When the chef inserts a potato to the input hatch, the kitchen system shall peel the potato.
     - When continuous ignition is commanded by the aircraft, the control system shall switch on continuous ignition.
     - When an Unregistered Device is plugged into a USB port, the OS shall attempt to locate and load the driver for the device.

3. **State-Driven Requirements**
   - **Pattern:**
     ```
     While <in a state>, the <system> shall <system response>.
     ```
   - **Examples:**
     - While the kitchen system is in maintenance mode, the kitchen system shall reject all input.
     - While the aircraft is in-flight, the control system shall maintain engine fuel flow above XXlbs/sec.
     - While in Low Power Mode, the software shall keep the display brightness at the Minimum Level.

4. **Unwanted Behavior Requirements**
   - **Pattern:**
     ```
     If <optional preconditions> <trigger>, then the <system> shall <system response>.
     ```
   - **Examples:**
     - If a spoon is inserted to the input hatch, then the kitchen system shall eject the spoon.
     - If the computed airspeed fault flag is set, then the control system shall use modeled airspeed.
     - If the memory checksum is invalid, then the software shall display an error message.

5. **Optional Feature Requirements**
   - **Pattern:**
     ```
     Where <feature>, the <system> shall <system response>.
     ```
   - **Examples:**
     - Where the kitchen system has a food freshness sensor, the kitchen system shall detect rotten foodstuffs.
     - Where hardware encryption is installed, the software shall encrypt data using the hardware instead of using a software algorithm.
     - Where a HDMI port is present, the software shall allow the user to select HD content for viewing.

6. **Complex Requirements**
   - **Pattern:**
     ```
     While <precondition(s)>, When <trigger>, the <system> shall <system response>.
     ```
     *or any combination of multiple EARS clauses.*
   - **Examples:**
     - When the landing gear button is depressed once, if the software detects that the landing gear does not lock into position, then the software shall sound an alarm.
     - While in start up mode, when the software detects an external flash card, the software shall use the external flash card to store photos.
     - Where a second optical drive is installed, when the user selects to copy disks, the software shall display an option to copy directly from one optical drive to the other.

**Ruleset:**

- **Clause Order:** The clauses must appear in the following order if multiple are present:
  1. While
  2. When
  3. Where
  4. If
  5. Then
  6. shall

- **Keywords:**
  - **While:** Denotes a state-driven requirement.
  - **When:** Denotes an event-driven requirement.
  - **Where:** Denotes an optional feature requirement.
  - **If/Then:** Denotes unwanted behavior requirements.
  - **shall:** Specifies the system response.

**Usage Tips:**

- Ensure that each requirement adheres to the correct pattern and clause order.
- Use the appropriate keywords to clearly define the nature of the requirement.
- For complex behaviors, combine multiple EARS patterns while maintaining the correct clause sequence.

===================================
"""
    print(info)

def parse_arguments():
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(description='Assess requirements for EARS syntax compliance.')
    parser.add_argument('input_file', nargs='?', help='Path to the input file containing requirements.')
    parser.add_argument('-o', '--output', help='Path to the output file.', default=None)
    parser.add_argument('-f', '--format', 
                        choices=['terminal', 'txt', 'csv', 'md', 'org'], 
                        default='terminal', 
                        help='Output format: terminal, txt, csv, md, org. Default is terminal.')
    parser.add_argument('-i', '--info', action='store_true', help='Display information about EARS syntax and exit.')
    return parser.parse_args()

def main():
    args = parse_arguments()

    if args.info:
        print_ears_info()
        sys.exit(0)

    if not args.input_file:
        print("Error: Input file is required unless using the --info flag.", file=sys.stderr)
        sys.exit(1)

    requirements = read_requirements(args.input_file)
    validator = EARSValidator()
    report = generate_report(requirements, validator)
    output_results(report, args.format, args.output)

if __name__ == '__main__':
    main()
