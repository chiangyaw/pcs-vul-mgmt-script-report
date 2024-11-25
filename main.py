import requests
import csv
import json
import os

# Prisma Cloud API credentials
ACCESS_KEY = os.getenv("PRISMA_ACCESS_KEY")
SECRET_KEY = os.getenv("PRISMA_SECRET_KEY")
API_URL = os.getenv("PRISMA_URL")

# CSV file output header
csvheader = ["_id", "type", "scanTime","vulnerabilities.id","vulnerabilities.severity","vulnerabilities.cvss","vulnerabilities.status","vulnerabilities.cve","vulnerabilities.description","vulnerabilities.vecStr", "vulnerabilities.exploits", "vulnerabilities.riskFactors", "vulnerabilities.link", "vulnerabilities.type","osDistro"]

ci_csvheader = ["_id", "entityInfo._id", "entityInfo.type", "entityInfo.scanTime","entityInfo.vulnerabilities.id","entityInfo.vulnerabilities.severity","entityInfo.vulnerabilities.cvss","entityInfo.vulnerabilities.status","entityInfo.vulnerabilities.cve","entityInfo.vulnerabilities.description","entityInfo.vulnerabilities.vecStr", "entityInfo.vulnerabilities.exploits", "entityInfo.vulnerabilities.riskFactors", "entityInfo.vulnerabilities.link", "entityInfo.vulnerabilities.type","entityInfo.osDistro"]

if not ACCESS_KEY or not SECRET_KEY or not API_URL:
    raise ValueError("Environment variables PRISMA_ACCESS_KEY, PRISMA_SECRET_KEY & PRISMA_URL must be set")

def authenticate():
    """Authenticate with Prisma Cloud API and return the token."""
    url = f"{API_URL}/api/v1/authenticate"
    payload = json.dumps({
        "username": ACCESS_KEY, 
        "password": SECRET_KEY
    })
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    
    if response.status_code == 200:
        return response.json().get("token")
    else:
        raise Exception(f"Authentication failed: {response.status_code} {response.text}")

def fetch_vul_deployed_images(token):
    """Fetch Deployed images with vulnerabilities from Prisma Cloud."""
    url = f"{API_URL}/api/v1/images"  # Replace with the correct API endpoint
    payload = {}
    headers = {"Authorization": f"Bearer {token}", 'Accept': 'application/json'}
    response = requests.request("GET",url, headers=headers, data=payload)
    
    if response.status_code == 200:
        return response.json()  # Assume the API returns JSON
    else:
        raise Exception(f"Failed to fetch vulnerabilities: {response.status_code} {response.text}")
    
def fetch_vul_ci_images(token):
    """Fetch Deployed images with vulnerabilities from Prisma Cloud."""
    url = f"{API_URL}/api/v1/scans"  # Replace with the correct API endpoint
    payload = {}
    headers = {"Authorization": f"Bearer {token}", 'Accept': 'application/json'}
    response = requests.request("GET",url, headers=headers, data=payload)
    
    if response.status_code == 200:
        return response.json()  # Assume the API returns JSON
    else:
        raise Exception(f"Failed to fetch vulnerabilities: {response.status_code} {response.text}")
    
def fetch_vul_registry_images(token):
    """Fetch Deployed images with vulnerabilities from Prisma Cloud."""
    url = f"{API_URL}/api/v1/registry"  # Replace with the correct API endpoint
    payload = {}
    headers = {"Authorization": f"Bearer {token}", 'Accept': 'application/json'}
    response = requests.request("GET",url, headers=headers, data=payload)
    
    if response.status_code == 200:
        return response.json()  # Assume the API returns JSON
    else:
        raise Exception(f"Failed to fetch vulnerabilities: {response.status_code} {response.text}")


def write_to_file(data, file_name):
    """Write raw JSON data to a file."""
    with open(file_name, "w") as json_file:
        json.dump(data, json_file, indent=4)
    print(f"JSON data written to {file_name}")

def get_nested_value(data, key):
    """
    Retrieve a nested value from a dictionary or list using a dot-separated key.

    Args:
        data (dict or list): The dictionary or list to search in.
        key (str): Dot-separated key representing the path to the value.

    Returns:
        Any: The value at the specified key path, or None if the path is invalid.
    """
    keys = key.split(".")
    value = data
    for k in keys:
        if isinstance(value, dict):
            value = value.get(k)
        elif isinstance(value, list):
            # Handle list by extracting values from each element, if possible
            value = [get_nested_value(item, k) for item in value]
            # Flatten single-element lists
            if len(value) == 1:
                value = value[0]
        else:
            return None
    return value

def json_to_table_with_double_nested_list(headers, json_data, nested_key, double_nested_key, output_file):
    """
    Converts unstructured JSON data with double nested lists into a table format.

    Args:
        headers (list): List of column names (dot-separated for nested keys).
        json_data (list or dict): Unstructured JSON data.
        nested_key (str): Key representing the first-level nested list to flatten (e.g., "vulnerabilities").
        double_nested_key (str): Key representing the second-level nested list to flatten (e.g., "exploits").
        output_file (str): File name to save the resulting table in CSV format.

    Returns:
        list: A list of rows representing the table.
    """
    if isinstance(json_data, dict):
        json_data = [json_data]  # Wrap single dict into a list for processing

    if not isinstance(json_data, list):
        raise ValueError("Input JSON data must be a dictionary or a list of dictionaries.")

    table = []
    for item in json_data:
        # Extract the first-level nested list
        nested_items = item.get(nested_key, [])
        if not isinstance(nested_items, list):
            nested_items = [nested_items]  # Handle single nested item as a list

        for nested_item in nested_items:
            # Extract the second-level nested list
            if nested_item is not None:
                double_nested_items = nested_item.get(double_nested_key, [])
            if not isinstance(double_nested_items, list):
                double_nested_items = [double_nested_items]  # Handle single item as a list
            for double_nested_item in double_nested_items:                                
                row = []
                for header in headers:
                    value = ""
                    if header.startswith(f"{nested_key}."):
                        if header.split(".",1)[1] == "exploits":
                            if get_nested_value(double_nested_item, "source") == "cisa-kev":
                                value = get_nested_value(double_nested_item, "link")
                        # Extract values from the first-level nested item
                        else:
                            key_path = header.split(".", 1)[1]
                            value = get_nested_value(nested_item, key_path)
                            if header.split(".",1)[1] == "riskFactors":
                                #value = value.replace("{","").replace("}", "").replace(":", "")
                                value = ", ".join(value.keys())
                    else:
                        # Extract values from the top-level item
                        value = get_nested_value(item, header)
                    row.append(value)
                table.append(row)

    # Write the table to a CSV file
    with open(output_file, mode="w", newline="") as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(headers)  # Write the header row
        csv_writer.writerows(table)   # Write the data rows

    print(f"Table written to {output_file}")
    return table

def json_to_table_with_triple_nested_list(headers, json_data, nested_key, double_nested_key, triple_nested_key, output_file):
    """
    Converts unstructured JSON data with tripe nested lists into a table format. This is specifically created to handle JSON data for CI vulnerability 

    Args:
        headers (list): List of column names (dot-separated for nested keys).
        json_data (list or dict): Unstructured JSON data.
        nested_key (str): Key representing the first-level nested list to flatten (e.g., "entityInfo").
        double_nested_key (str): Key representing the second-level nested list to flatten (e.g., "vulnerabilities").
        tripe_nested_key (str): Key representing the third-level nested list to platten (e.g., "exploits").
        output_file (str): File name to save the resulting table in CSV format.

    Returns:
        list: A list of rows representing the table.
    """
    if isinstance(json_data, dict):
        json_data = [json_data]  # Wrap single dict into a list for processing

    if not isinstance(json_data, list):
        raise ValueError("Input JSON data must be a dictionary or a list of dictionaries.")

    table = []
    for item in json_data:
        # Extract the first-level nested list
        nested_items = item.get(nested_key, [])
        if not isinstance(nested_items, list):
            nested_items = [nested_items]  # Handle single nested item as a list

        for nested_item in nested_items:
            # Extract the second-level nested list
            if nested_item is not None:
                double_nested_items = nested_item.get(double_nested_key, [])
            if not isinstance(double_nested_items, list):
                double_nested_items = [double_nested_items]  # Handle single item as a list
            for double_nested_item in double_nested_items:
                if double_nested_item is not None:
                    triple_nested_items = double_nested_item.get(triple_nested_key, [])
                if not isinstance(triple_nested_items, list):
                    triple_nested_items = [triple_nested_items]
                for triple_nested_item in triple_nested_items:
                    row = []
                    for header in headers:
                        value = ""
                        if header.startswith(f"{nested_key}.{double_nested_key}."):
                            if header.split(".",2)[2] == "exploits":
                                if get_nested_value(triple_nested_item, "source") == "cisa-kev":
                                    value = get_nested_value(triple_nested_item, "link")
                            else: 
                                key_path = header.split(".", 2)[2]
                                value = get_nested_value(double_nested_item, key_path)
                                if header.split(".", 2)[2] == "riskFactors":
                                    if value is not None:
                                        value = ", ".join(value.keys())
                        elif header.startswith(f"{nested_key}."):
                            key_path = header.split(".", 1)[1]
                            value = get_nested_value(nested_item, key_path)
                            # Extract values from the first-level nested item
                        else:
                            # Extract values from the top-level item
                            value = get_nested_value(item, header)
                        row.append(value)
                    table.append(row)

    # Write the table to a CSV file
    with open(output_file, mode="w", newline="") as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(headers)  # Write the header row
        csv_writer.writerows(table)   # Write the data rows

    print(f"Table written to {output_file}")
    return table

def main():
    try:
        print("Authenticating...")
        token = authenticate()
        print("Fetching data for deployed images...")
        fetched_json_data = fetch_vul_deployed_images(token)
        ## Optional function to obtain the data in json, to determine what are the other headers you can add on to the CSV
        #write_to_file(fetched_json_data, "deployed_images_vul.json")  
        print("Exporting to CSV for deployed images...")
        json_to_table_with_double_nested_list(
            headers=csvheader, 
            json_data=fetched_json_data, 
            nested_key="vulnerabilities", 
            double_nested_key="exploits",
            output_file="deployed_images_vul.csv"
            )
        print("Fetching data for CI images...")
        fetched_json_data = fetch_vul_ci_images(token)
        print("Exporting to CSV for CI images...")
        json_to_table_with_triple_nested_list(
            headers=ci_csvheader, 
            json_data=fetched_json_data, 
            nested_key="entityInfo", 
            double_nested_key="vulnerabilities",
            triple_nested_key="exploits",
            output_file="ci_images_vul.csv"
            )
        print("Fetching data for registry images...")
        fetched_json_data = fetch_vul_registry_images(token)
        print("Exporting to CSV for registry images...")
        json_to_table_with_double_nested_list(
            headers=csvheader, 
            json_data=fetched_json_data, 
            nested_key="vulnerabilities", 
            double_nested_key="exploits",
            output_file="registry_images_vul.csv"
            )

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
