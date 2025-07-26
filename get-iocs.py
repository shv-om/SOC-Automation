import re
import pandas as pd

def extract_iocs(text):
    # Normalize obfuscations
    text = text.replace('hxxp', 'http').replace('hxxps', 'https')
    text = re.sub(r'\[\.\]|\(\.\)|\{\.}', '.', text)

    # Known TLDs (expandable)
    known_tlds = {
        'com', 'net', 'org', 'info', 'biz', 'co', 'io', 'gov', 'edu', 'ru', 'cn', 'uk',
        'de', 'jp', 'in', 'xyz', 'top', 'site', 'online', 'tech', 'store', 'us', 'ca',
        'au', 'fr', 'eu', 'ch', 'nl', 'se', 'no', 'es', 'it', 'tv', 'me', 'cc', 'ws',
        'tk', 'ml', 'ga', 'cf', 'gq', 'gl', 'to', 'pw', 'fm', 'am', 'pro', 'name',
        'mobi', 'jobs', 'museum', 'travel', 'int', 'mil', 'arpa', 'onion'
    }

    # Regex patterns
    url_pattern = r'https?://[^\s/$.?#].[^\s]*'
    ip_patterns = {
        'ipv4': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'ipv6': r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b'
    }
    hash_patterns = {
        'MD5': r'\b[a-fA-F0-9]{32}\b',
        'SHA1': r'\b[a-fA-F0-9]{40}\b',
        'SHA256': r'\b[a-fA-F0-9]{64}\b'
    }
    email_pattern = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    domain_like_pattern = r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'

    # Extract domain-like strings
    domain_like = re.findall(domain_like_pattern, text)

    domains = []
    filenames = []

    # need to differ between domains and filenames. Since both have similar pattern to match for
    for item in domain_like:
        tld = item.split('.')[-1].lower()
        if tld in known_tlds:
            domains.append(item)
        else:
            filenames.append(item)

    # Extract other IOCs
    iocs = {
        'URLs': re.findall(url_pattern, text),
        'Domains': domains,
        'IP': [],
        'Filenames': filenames,
        'Emails': re.findall(email_pattern, text),
        'Hash': []
    }

    for name, pattern in ip_patterns.items():
        matches = re.findall(pattern, text)
        iocs['IP'].extend(matches)

    # Add hashes
    for name, pattern in hash_patterns.items():
        matches = re.findall(pattern, text)
        iocs['Hash'].extend(matches)


    return iocs

alertdata = pd.read_excel('Incident_Details.xlsx')

# Extract the Textual column. Adjust the code for multiple columns.
textual_data = alertdata['Analysis']

iocs = []

# update IOCs in a list of dictionary
for text in textual_data:
    iocs.append(extract_iocs(text))
    for i in iocs:
        for k, v in i.items():
            i.update({k: list(set(v))})

updatedf = alertdata.copy(deep=True)

# Updating the new DataFrame with the extracted values. If it doesn't contain some type of IOCs then it'll just have NaN
for i in range(len(iocs)):
    for k, v in iocs[i].items():
        v = ', '.join(v).lower() if v else 'NaN'
        updatedf.loc[i, k] = v
        print(f"Updated Row {i} for Column {k} :-> \t{v}")

# Write the updated DataFrame to new excel file which can be used in any model as a DataFrame
updatedf.to_excel('updated_dataframe.xlsx')