# Read the content from a file
file_path = '.\..\Mapping.md'  # Replace this with the actual file path
with open(file_path, 'r') as file:
    file_content = file.read()

# Splitting the content based on markdown headers
sections = file_content.split("## ")

# Creating a dictionary to store tactic names and their corresponding entry counts
tactic_entry_count = {}

# Iterate through sections starting from index 1 to skip the initial empty string
for section in sections[1:]:
    # Splitting each section by newline to get individual lines
    lines = section.split("\n")
    
    # Extracting the tactic name (header)
    tactic_name = lines[0].strip()
    
    # Counting the rows in the table (excluding header row and dashes)
    table_entries = len([line for line in lines if "|" in line]) - 3 if len(lines) > 3 else 0
    
    # Storing tactic name and entry count in the dictionary
    tactic_entry_count[tactic_name] = table_entries + 1

# Creating a Markdown table with the tactic names and entry counts
markdown_table = "| Tactic | Entry Count |\n| --- | --- |\n"
for tactic, count in tactic_entry_count.items():
    markdown_table += f"| {tactic} | {count} |\n"

# Printing the Markdown table
print(markdown_table)
