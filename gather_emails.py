import requests
from bs4 import BeautifulSoup
import re

def google_dork(domain):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    query = f"site:{domain} email"
    url = f"https://www.google.com/search?q={query}"
    response = requests.get(url, headers=headers)
    soup = BeautifulSoup(response.text, 'html.parser')

    emails = set()
    for g in soup.find_all(class_='g'):
        links = g.find_all('a')
        for link in links:
            href = link.get('href')
            if href and "http" in href:
                emails.update(extract_emails(href))
    return emails

def extract_emails(url):
    response = requests.get(url)
    emails = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", response.text))
    return emails

def hunter_io(domain):
    api_key = "4d64ffa36f57f4345a0a246b37c91a93141ef27f"  # Replace with your actual API key
    url = f'https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}'
    response = requests.get(url)
    data = response.json()
    
    emails = []
    for email_data in data['data']['emails']:
        email_info = {
            'email_address': email_data['value'],
            'first_name': email_data.get('first_name'),
            'last_name': email_data.get('last_name'),
            'position': email_data.get('position'),
            'seniority': email_data.get('seniority'),
            'department': email_data.get('department'),
            'linkedin': email_data.get('linkedin'),
            'twitter': email_data.get('twitter'),
            'phone_number': email_data.get('phone_number'),
            'is_alive': verify_email_with_hunter(email_data['value'], api_key)
        }
        emails.append(email_info)
    return emails

def verify_email_with_hunter(email, api_key):
    url = f'https://api.hunter.io/v2/email-verifier?email={email}&api_key={api_key}'
    try:
        response = requests.get(url)
        if response.status_code == 200:
            result = response.json()
            return result.get('data', {}).get('status') == 'valid'
        else:
            return False
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return False

def filter_alive_emails(emails):
    alive_emails = []
    for email in emails:
        # if verify_email_with_hunter(email['email_address'], "4d64ffa36f57f4345a0a246b37c91a93141ef27f"):
        alive_emails.append(email)
    return alive_emails


# def save_emails_to_db(emails, campaign_id):
#     for email_data in emails:
#         email_dict = dict(email_data)
#         email = Email(
#             campaign_id=campaign_id,
#             email_address=email_dict['email_address'],
#             first_name=email_dict.get('first_name'),
#             last_name=email_dict.get('last_name'),
#             position=email_dict.get('position'),
#             seniority=email_dict.get('seniority'),
#             department=email_dict.get('department'),
#             linkedin=email_dict.get('linkedin'),
#             twitter=email_dict.get('twitter'),
#             phone_number=email_dict.get('phone_number'),
#             is_alive=email_dict.get('is_alive')
#         )
#         db.session.add(email)
#     db.session.commit()
