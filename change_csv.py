import pandas as pd

# Load the JSON file
file_path = '/Users/chonakyung/modelmodel/packet_info.json'
data = pd.read_json(file_path)

# Save as CSV
csv_file_path = file_path.replace('.json', '.csv')
data.to_csv(csv_file_path, index=False)

csv_file_path
