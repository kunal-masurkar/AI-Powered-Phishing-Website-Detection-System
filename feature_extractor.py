import re
import ssl
import socket
import whois
import tldextract
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime
import warnings
import time
import logging
from requests.exceptions import RequestException, Timeout, ConnectionError, SSLError
from urllib3.exceptions import InsecureRequestWarning

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Suppress only the single warning from urllib3 needed.
warnings.filterwarnings('ignore', category=InsecureRequestWarning)
warnings.filterwarnings('ignore', category=UserWarning)

class URLFeatureExtractor:
    def __init__(self):
        self.suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'site',
                                'online', 'click', 'link', 'website', 'space', 'tech', 'info']
        self.suspicious_words = [
            'login', 'signin', 'signup', 'account', 'verify', 'confirm',
            'secure', 'bank', 'paypal', 'ebay', 'amazon', 'apple', 'microsoft',
            'netflix', 'facebook', 'google', 'password', 'security', 'update',
            'suspicious', 'verify', 'validate', 'secure', 'account', 'login',
            'signin', 'password', 'banking', 'paypal', 'ebay', 'amazon'
        ]
        
        # Configure timeouts
        self.timeout = 3  # Reduced timeout to 3 seconds
        self.session = requests.Session()
        self.session.timeout = self.timeout
        
        # Configure retries
        self.max_retries = 1  # Reduced retries to 1
        self.retry_delay = 0.2  # Reduced delay to 0.2 seconds
        
        # Configure WHOIS timeout
        socket.setdefaulttimeout(self.timeout)
        
        # Configure session headers
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Skip WHOIS lookups flag
        self.skip_whois = True  # Set to True to skip WHOIS lookups

    def extract_features(self, url):
        """Extract all features from a given URL."""
        features = {}
        
        try:
            # Basic URL features (no network calls)
            features.update(self._get_url_based_features(url))
            
            # Domain features (no network calls)
            features.update(self._get_domain_based_features(url))
            
            # SSL features (with timeout)
            try:
                ssl_features = self._get_ssl_features(url)
                features.update(ssl_features)
            except Exception as e:
                logger.debug(f"SSL check failed for {url}: {str(e)}")
                features.update({
                    'has_ssl': 0,
                    'ssl_expiry_days': 0
                })
            
            # WHOIS features (with timeout) - Skip if flag is set
            if not self.skip_whois:
                try:
                    whois_features = self._get_whois_features(url)
                    features.update(whois_features)
                except Exception as e:
                    logger.debug(f"WHOIS query failed for {url}: {str(e)}")
                    features.update({
                        'domain_age_days': 0,
                        'domain_expiry_days': 0
                    })
            else:
                features.update({
                    'domain_age_days': 0,
                    'domain_expiry_days': 0
                })
            
            # HTML features (with timeout and retries)
            try:
                html_features = self._get_html_features(url)
                features.update(html_features)
            except Exception as e:
                logger.debug(f"HTML analysis failed for {url}: {str(e)}")
                features.update({
                    'num_forms': 0,
                    'num_inputs': 0,
                    'num_iframes': 0,
                    'num_external_links': 0,
                    'num_internal_links': 0
                })
            
        except Exception as e:
            logger.error(f"Error extracting features for {url}: {str(e)}")
            features = self._get_default_features()
        
        return features
    
    def _get_url_based_features(self, url):
        """Extract features based on URL structure."""
        features = {}
        
        # Add http/https if not present
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        parsed = urlparse(url)
        
        # URL length
        features['url_length'] = len(url)
        
        # Number of dots in URL
        features['num_dots'] = url.count('.')
        
        # Number of hyphens in URL
        features['num_hyphens'] = url.count('-')
        
        # Number of underscores in URL
        features['num_underscores'] = url.count('_')
        
        # Number of slashes in URL
        features['num_slashes'] = url.count('/')
        
        # Number of question marks in URL
        features['num_question_marks'] = url.count('?')
        
        # Number of equal signs in URL
        features['num_equal_signs'] = url.count('=')
        
        # Number of @ symbols in URL
        features['num_at_symbols'] = url.count('@')
        
        # Number of suspicious words in URL
        features['num_suspicious_words'] = sum(1 for word in self.suspicious_words if word in url.lower())
        
        return features
    
    def _get_domain_based_features(self, url):
        """Extract features based on domain analysis."""
        features = {}
        
        try:
            extracted = tldextract.extract(url)
            domain = extracted.domain
            tld = extracted.suffix
            
            # Domain length
            features['domain_length'] = len(domain)
            
            # TLD length
            features['tld_length'] = len(tld)
            
            # Is suspicious TLD
            features['is_suspicious_tld'] = 1 if tld in self.suspicious_tlds else 0
            
            # Number of subdomains
            features['num_subdomains'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
            
            # Has IP in domain
            features['has_ip_in_domain'] = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0
            
        except Exception as e:
            print(f"Error in domain analysis: {str(e)}")
            features.update({
                'domain_length': 0,
                'tld_length': 0,
                'is_suspicious_tld': 0,
                'num_subdomains': 0,
                'has_ip_in_domain': 0
            })
            
        return features
    
    def _get_ssl_features(self, url):
        """Extract features based on SSL certificate."""
        features = {}
        
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # SSL certificate exists
                    features['has_ssl'] = 1
                    
                    # SSL certificate expiry
                    if cert and 'notAfter' in cert:
                        expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        features['ssl_expiry_days'] = (expiry_date - datetime.now()).days
                    else:
                        features['ssl_expiry_days'] = 0
                        
        except Exception as e:
            features.update({
                'has_ssl': 0,
                'ssl_expiry_days': 0
            })
            
        return features
    
    def _get_whois_features(self, url):
        """Extract features based on WHOIS information with improved error handling."""
        features = {
            'domain_age_days': 0,
            'domain_expiry_days': 0
        }
        
        try:
            # Extract domain from URL
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Skip WHOIS for certain domains
            if any(skip in domain.lower() for skip in ['localhost', '127.0.0.1', '::1']):
                return features
            
            # Set timeout for WHOIS query
            socket.setdefaulttimeout(self.timeout)
            
            # Use a context manager to ensure socket is closed
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                try:
                    # Perform WHOIS query with timeout
                    w = whois.whois(domain)
                    
                    # Process creation date
                    if w.creation_date:
                        if isinstance(w.creation_date, list):
                            creation_date = w.creation_date[0]
                        else:
                            creation_date = w.creation_date
                        if creation_date:
                            features['domain_age_days'] = (datetime.now() - creation_date).days
                    
                    # Process expiration date
                    if w.expiration_date:
                        if isinstance(w.expiration_date, list):
                            expiry_date = w.expiration_date[0]
                        else:
                            expiry_date = w.expiration_date
                        if expiry_date:
                            features['domain_expiry_days'] = (expiry_date - datetime.now()).days
                            
                except (Timeout, ConnectionError) as e:
                    logger.debug(f"WHOIS timeout/connection error for {url}: {str(e)}")
                except Exception as e:
                    logger.debug(f"WHOIS query failed for {url}: {str(e)}")
                    
        except Exception as e:
            logger.debug(f"Error in WHOIS feature extraction for {url}: {str(e)}")
        
        return features
    
    def _get_html_features(self, url):
        """Extract features based on HTML content."""
        features = {
            'num_forms': 0,
            'num_inputs': 0,
            'num_iframes': 0,
            'num_external_links': 0,
            'num_internal_links': 0
        }
        
        try:
            # Add http/https if not present
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            # Try to get the page content with timeout
            for attempt in range(self.max_retries + 1):
                try:
                    response = self.session.get(
                        url,
                        timeout=self.timeout,
                        verify=False,  # Disable SSL verification
                        allow_redirects=True
                    )
                    response.raise_for_status()
                    break
                except (Timeout, ConnectionError, SSLError) as e:
                    if attempt == self.max_retries:
                        logger.warning(f"Failed to fetch {url} after {self.max_retries + 1} attempts: {str(e)}")
                        return features
                    time.sleep(self.retry_delay)
                except Exception as e:
                    logger.warning(f"Unexpected error fetching {url}: {str(e)}")
                    return features
            
            # Parse HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Count forms
            features['num_forms'] = len(soup.find_all('form'))
            
            # Count input fields
            features['num_inputs'] = len(soup.find_all('input'))
            
            # Count iframes
            features['num_iframes'] = len(soup.find_all('iframe'))
            
            # Count links
            links = soup.find_all('a', href=True)
            base_domain = urlparse(url).netloc
            
            for link in links:
                href = link['href']
                try:
                    parsed_href = urlparse(href)
                    if parsed_href.netloc:
                        if parsed_href.netloc == base_domain:
                            features['num_internal_links'] += 1
                        else:
                            features['num_external_links'] += 1
                except Exception:
                    continue
                    
        except Exception as e:
            logger.warning(f"Error analyzing HTML for {url}: {str(e)}")
            
        return features

    def _get_default_features(self):
        """Return default feature values when extraction fails."""
        return {
            'url_length': 0,
            'num_dots': 0,
            'num_hyphens': 0,
            'num_underscores': 0,
            'num_slashes': 0,
            'num_question_marks': 0,
            'num_equal_signs': 0,
            'num_at_symbols': 0,
            'num_suspicious_words': 0,
            'domain_length': 0,
            'tld_length': 0,
            'is_suspicious_tld': 0,
            'num_subdomains': 0,
            'has_ip_in_domain': 0,
            'has_ssl': 0,
            'ssl_expiry_days': 0,
            'domain_age_days': 0,
            'domain_expiry_days': 0,
            'num_forms': 0,
            'num_inputs': 0,
            'num_iframes': 0,
            'num_external_links': 0,
            'num_internal_links': 0
        } 