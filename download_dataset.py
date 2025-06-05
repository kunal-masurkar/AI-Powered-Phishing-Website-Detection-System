import requests
import pandas as pd
import os
from datetime import datetime
import time
import json
from bs4 import BeautifulSoup

def download_phishing_urls():
    """Download phishing URLs from PhishTank."""
    print("Downloading phishing URLs from PhishTank...")
    
    # PhishTank API endpoint
    url = "http://data.phishtank.com/data/online-valid.json"
    
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for bad status codes
        data = response.json()
        
        # Extract URLs and metadata
        phishing_data = []
        for entry in data:
            try:
                # Convert timestamp to string if it's not already
                timestamp = str(entry.get('timestamp', ''))
                
                phishing_data.append({
                    'url': entry.get('url', ''),
                    'verified': entry.get('verified', False),
                    'timestamp': timestamp,
                    'target': entry.get('target', ''),
                    'submission_time': entry.get('submission_time', '')
                })
            except Exception as e:
                print(f"Warning: Skipping entry due to error: {str(e)}")
                continue
        
        if not phishing_data:
            raise Exception("No valid phishing URLs found in the response")
        
        # Create DataFrame
        df = pd.DataFrame(phishing_data)
        
        # Save to CSV
        df.to_csv('data/phishing_urls.csv', index=False)
        print(f"Downloaded {len(df)} phishing URLs")
        
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to PhishTank: {str(e)}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error parsing PhishTank response: {str(e)}")
        return None
    except Exception as e:
        print(f"Error downloading phishing URLs: {str(e)}")
        return None

def download_legitimate_urls():
    """Download legitimate URLs from the Tranco top sites list."""
    print("Downloading legitimate URLs from Tranco Top Sites...")
    
    # Create data directory if it doesn't exist
    data_dir = 'data'
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
    
    tranco_url = "https://tranco-list.eu/top-1m.csv.zip"
    csv_zip_path = os.path.join(data_dir, 'tranco_top1m.csv.zip')
    csv_path = os.path.join(data_dir, 'tranco_top1m.csv')
    
    try:
        # Download the zipped CSV file
        print("Downloading Tranco list...")
        response = requests.get(tranco_url, stream=True)
        response.raise_for_status()  # Raise an exception for bad status codes
        
        with open(csv_zip_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        # Unzip the CSV file
        print("Extracting CSV file...")
        import zipfile
        with zipfile.ZipFile(csv_zip_path, 'r') as zip_ref:
            # Get the name of the file inside the zip
            file_name = zip_ref.namelist()[0]
            # Extract the file
            zip_ref.extract(file_name, data_dir)
            # Rename the extracted file to our desired name
            os.rename(os.path.join(data_dir, file_name), csv_path)
        
        # Read the CSV and extract the top 100 domains
        print("Processing domains...")
        df = pd.read_csv(csv_path, header=None, names=['rank', 'domain'])
        top_n = 100
        legitimate_data = []
        for _, row in df.head(top_n).iterrows():
            legitimate_data.append({
                'url': f"https://{row['domain']}",
                'rank': row['rank']
            })
        
        # Save to CSV
        legit_df = pd.DataFrame(legitimate_data)
        legit_df.to_csv(os.path.join(data_dir, 'legitimate_urls.csv'), index=False)
        print(f"Downloaded {len(legit_df)} legitimate URLs from Tranco.")
        
        # Clean up downloaded files
        print("Cleaning up temporary files...")
        if os.path.exists(csv_zip_path):
            os.remove(csv_zip_path)
        if os.path.exists(csv_path):
            os.remove(csv_path)
        
    except requests.exceptions.RequestException as e:
        print(f"Error downloading Tranco list: {str(e)}")
        return None
    except zipfile.BadZipFile as e:
        print(f"Error extracting zip file: {str(e)}")
        return None
    except Exception as e:
        print(f"Error downloading legitimate URLs: {str(e)}")
        return None

def create_balanced_dataset():
    """Create a balanced dataset for training."""
    print("Creating balanced dataset...")
    
    try:
        # Load datasets
        phishing_df = pd.read_csv('data/phishing_urls.csv')
        legitimate_df = pd.read_csv('data/legitimate_urls.csv')
        
        # Balance the dataset
        min_samples = min(len(phishing_df), len(legitimate_df))
        
        # Randomly sample equal number of URLs from each class
        phishing_df = phishing_df.sample(n=min_samples, random_state=42)
        legitimate_df = legitimate_df.sample(n=min_samples, random_state=42)
        
        # Combine datasets
        combined_df = pd.concat([
            phishing_df[['url']].assign(label=1),  # 1 for phishing
            legitimate_df[['url']].assign(label=0)  # 0 for legitimate
        ], ignore_index=True)
        
        # Shuffle the dataset
        combined_df = combined_df.sample(frac=1, random_state=42)
        
        # Save balanced dataset
        combined_df.to_csv('data/balanced_dataset.csv', index=False)
        print(f"Created balanced dataset with {len(combined_df)} URLs")
        
    except Exception as e:
        print(f"Error creating balanced dataset: {str(e)}")
        return None

def main():
    # Create data directory if it doesn't exist
    if not os.path.exists('data'):
        os.makedirs('data')
    
    # Download datasets
    download_phishing_urls()
    download_legitimate_urls()
    
    # Create balanced dataset
    create_balanced_dataset()
    
    print("\nDataset preparation completed!")

if __name__ == "__main__":
    main() 