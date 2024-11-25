# Prisma Cloud Vulnerability Fetcher Script for Reporting
This is a custom python script created for vulnerability fetching, and reporting. The script connects to the Prisma Cloud API,  authenticates using an access key and secret key, and retrieves a list of assets with vulnerabilities. The script outputs the data in CSV format and provides options to customize the output, including handling nested JSON structures.

## Features
* Authenticate to Prisma Cloud API using access and secret keys.
* Fetch and process asset vulnerability data, including nested details.
* Output results in a clean CSV format.
* Handles nested and multi-layered JSON structures.

## Requirements
### System Requirements
* Python 3.8 or later
### Python Libraries
The script requires the following Python libraries:
* ```requests```

To install the dependencies, run:
```
pip install -r requirements.txt
```

### Usage
1. Clone the repository or download the script:
```
git clone https://github.com/chiangyaw/pcs-vul-mgmt-script-report.git
cd pcs-vul-mgmt-script-report
```
2. Create a virtual environment (optional but recommended):
```
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```
3. install dependencies:
```
pip install -r requirements.txt
```
4. Update environment variables for Prisma Cloud authentication:
    * set the following environment variables in your shell:
    ```
    export PRISMA_ACCESS_KEY="your_access_key"
    export PRISMA_SECRET_KEY="your_secret_key"
    export PRISMA_URL="your_prisma_cloud_url"
    ```

5. Run the script"
```
python main.py
```

### Script Options
* Customize output filename: The script covers 3 major areas, deployed images, CI images and registry images. All the file names can be customized
* Customize field required for CSV: The script fetches a lot of data from Prisma Cloud, and you might not need all data that are available. Hence, we have 2 lists in the script that can be customized:
    - ```csvheader```
    - ```ci_csvheader```
To understand what data are available, you can either look into the ```sample.json``` or uncomment the ```write_to_file``` line on the ```main``` function. 

### Example Output
The script generates multiple CSV files, and the format will be similar to ```sample_deployed_images_vul.csv```. 