#!/usr/bin/python3
import re
import requests
import argparse
import base64
import csv
import sys
import logging
import os
import json
from datetime import datetime
from logging.handlers import RotatingFileHandler
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Configure logging
def setup_logging(log_level=logging.INFO):
    """Configure logging with both file and console handlers."""
    # Create logs directory if it doesn't exist
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    # Create a custom logger
    logger = logging.getLogger("socgholish_finder")
    logger.setLevel(log_level)
    
    # Prevent duplicate handlers in case of multiple calls
    if logger.handlers:
        return logger
    
    # Format for logs
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    formatter = logging.Formatter(log_format)
    
    # File handler with rotation (5MB per file, keep 5 backups)
    log_file = os.path.join(log_dir, f"socgholish_{datetime.now().strftime('%Y%m%d')}.log")
    file_handler = RotatingFileHandler(
        log_file, 
        maxBytes=5*1024*1024,  # 5MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(log_level)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)  # Only show INFO and above in console
    
    # Add handlers to the logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    # Set up root logger to capture third-party logs
    logging.basicConfig(handlers=[file_handler, console_handler], level=logging.WARNING)
    
    # Suppress noisy loggers
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    
    return logger

# Initialize logger
logger = setup_logging()

def log_http_request(response, **kwargs):
    """Log HTTP request details."""
    if logger.isEnabledFor(logging.DEBUG):
        request = response.request
        
        log_data = {
            'method': request.method,
            'url': request.url,
            'status_code': response.status_code,
            'elapsed': response.elapsed.total_seconds(),
            'request_headers': dict(request.headers),
            'response_headers': dict(response.headers),
        }
        
        # Log request body if present and not too large
        if request.body and len(str(request.body)) < 1000:
            log_data['request_body'] = request.body
            
        logger.debug("HTTP Request/Response:\n%s", json.dumps(log_data, indent=2, default=str))

# TODO: Precompile REGEX
# TODO: Find more indicators
# TODO: Remove headers as a flag, we can just randomize in the script if that matters
# TODO: Decode the %2 variant of the SocGholish script
# TODO: Multi-threading on GetWebsite for CSV

# REGEX Indicators for the currently found SocGholish js
indicators = [
    ("V2luZG93cw","VjJsdVpHOTNjdz09",r".W.i.n.d.o.w.s."),
    r"\w{2}\s*=\s*document\.referrer;\s*var\s\w{2}\s*=\s*window\.location\.href;var\s*\w{2}\s*=\s*navigator\.userAgent;",
    r"\w{2}\s*=\s*document\.createElement\W*script\W*\s*\w{2}\.type\s*=\s*\W*[a-zA-Z\/]*\W*\s*\w{2}\.async\s*=\s*(?:true|false);\s*\w{2}\.src\s*=\s*\w{2}"
]

def GetWebsite(url, headers=None, timeout=10):
    """
    Fetches content from a URL with proper error handling and protocol fallback.
    
    Args:
        url (str): The URL to fetch
        headers (dict, optional): Headers to include in the request
        timeout (int): Request timeout in seconds (default: 10)
        
    Returns:
        requests.Response: Response object if successful, None otherwise
    """
    if not isinstance(url, str) or not url.strip():
        logger.error(f"Invalid URL provided: {url}")
        return None

    # Ensure headers has a User-Agent
    headers = headers or {}
    if 'User-Agent' not in headers:
        headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'

    # Try with existing protocol if specified
    if url.startswith(('http://', 'https://')):
        try:
            logger.debug(f"Fetching URL with existing protocol: {url}")
            response = requests.get(
                url, 
                headers=headers, 
                timeout=timeout, 
                allow_redirects=True,
                verify=True
            )
            response.raise_for_status()
            log_http_request(response)
            return response
            
        except requests.exceptions.SSLError as e:
            logger.warning(f"SSL certificate verification failed for {url}: {str(e)}")
            return None
            
        except requests.exceptions.HTTPError as e:
            logger.warning(f"HTTP error for {url}: {e.response.status_code} - {str(e)}")
            return None
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching {url}: {str(e)}", exc_info=logger.isEnabledFor(logging.DEBUG))
            return None
    
    # Try with https:// first, then fall back to http://
    for protocol in ['https://', 'http://']:
        full_url = protocol + url.lstrip('/')
        logger.debug(f"Trying protocol {protocol} for URL: {full_url}")
        
        try:
            response = requests.get(
                full_url,
                headers=headers,
                timeout=timeout,
                allow_redirects=True,
                verify=True
            )
            response.raise_for_status()
            log_http_request(response)
            return response
            
        except requests.exceptions.SSLError as e:
            logger.warning(f"SSL error with {full_url}: {str(e)}")
            if protocol == 'http://':  # If we've tried both protocols
                return None
            continue
            
        except requests.exceptions.HTTPError as e:
            logger.warning(f"HTTP error for {full_url}: {e.response.status_code} - {str(e)}")
            continue
            
        except requests.exceptions.RequestException as e:
            logger.debug(f"Error with {full_url}: {str(e)}")
            if protocol == 'http://':  # If we've tried both protocols
                logger.error(f"Failed to fetch URL after trying both protocols: {url}")
                return None
            continue
    
    return None

def ParseWebsite(url, ua):
    """
    Parse a website and extract JavaScript content from script tags.
    
    Args:
        url (str): The URL of the website to parse
        ua (str): User-Agent string to use for requests
        
    Returns:
        list: List of tuples containing (source_url, script_content)
    """
    scripts = []
    
    # Validate input
    if not url or not isinstance(url, str):
        print("Error: Invalid URL provided to ParseWebsite")
        return scripts
    
    # Fetch the website content
    response = GetWebsite(url, headers={'User-Agent': ua})
    if response is None:
        print(f"Failed to fetch website: {url}")
        return scripts
    
    try:
        # Parse the HTML content
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Process each script tag
        for script_tag in soup.find_all('script'):
            src = script_tag.get('src')
            
            # Handle inline scripts
            if src is None:
                if script_tag.string:  # Only add non-empty script content
                    scripts.append((url, script_tag.string))
                continue
                
            # Handle external scripts
            try:
                src_url = urljoin(url, src)
                if not src_url.startswith(('http://', 'https://')):
                    continue  # Skip non-http(s) URLs
                    
                script_response = GetWebsite(src_url, headers={'User-Agent': ua})
                if script_response is None:
                    continue
                    
                # Handle different content types
                content = script_response.content
                if isinstance(content, bytes):
                    try:
                        content = content.decode('utf-8', errors='replace')
                    except UnicodeDecodeError:
                        content = content.decode('latin-1', errors='replace')
                
                scripts.append((src_url, content))
                
            except Exception as e:
                print(f"Error processing script {src}: {str(e)}")
                continue
                
    except Exception as e:
        print(f"Error parsing website {url}: {str(e)}")
    
    return scripts

def FindSocGholish(scripts):
    potential_sg = []
    for s in scripts:
        hits = 0
        for i in indicators:
            if type(i) is tuple:
                for regex in i:
                    if re.search(regex,s[1],re.I): # This is a little computationally heavy - if we precompile the Rex we can save some effort
                        hits = hits + 1
            else:
                if re.search(i,s[1],re.I):
                    hits = hits + 1
        if hits > 0:
            potential_sg.append((s,hits))
    return potential_sg

def Stage2Url(script): # Only works for the known base64 SocGholish script
    src = re.search(r"\w{2}\.src\s*=\s*\w{2}\(\W*'(.*?)'\W*\)",script[1],re.I)
    url = src.group(1)
    decoded = []
    try:
        decoded.append(base64.b64decode(url).decode("UTF-8"))
        try:
            decoded.append(base64.b64decode(decoded[0]).decode("UTF-8"))
        except:
            pass
    except:
        pass
    decoded.append(url[1::2])
    for d in decoded:
        if ("report" in d) or (d[0] == "/"):
            return d
    return None

def scan(url,ua):
    print("Scanning website {} in progress...".format(url))
    scripts = ParseWebsite(url, ua)
    sg = FindSocGholish(scripts)
    if sg != []:
        stage2 = []
        for e in sg:
            print("Found potential SocGholish on {}!".format(e[0][0]))
            print("Potential injection script (matched {:d} out of {:d} indicators):".format(e[1],len(indicators)))
            print(e[0][1])
            print("")
            stage2.append(urljoin(url,Stage2Url(e[0])))
        print("Trying to extract stage 2 urls...")
        print("")
        print("Potential Stage 2 URLs:")
        for u in stage2:
            if "report" in u:
                print(u)
            else:
                response = GetWebsite(urljoin(url,u),headers={'Host': url.split('/')[2], 'User-Agent': ua, 'referer': url})
                s2url = Stage2Url(response.content)
                if s2url is not None:
                    print(s2url)             
    else:
        hit = False
        for script in scripts:
            if re.match(r"[A-Za-z0-9]{32,}", script[0].split("/")[-1]) != None:
                r = GetWebsite(script[0], headers={'User-Agent': ua})
                if r.content == b'':
                    hit = True
                    print("Found potential SocGholish on {}!".format(url))
                    print("Potential injection script (possible false-positive due to a weak indicator): {}".format(script[0]))
                    print("")
        if hit == False:
            print("Couldn't find any SocGholish payload :(")

def main():
    parser = argparse.ArgumentParser(description='SocGholish finder')
    parser.add_argument("-url", type=str, help="URL to check")
    parser.add_argument("-ua", "--user-agent", type=str, help="Specify User-Agent to use with the request")
    parser.add_argument("-f", "--filename", type=str, help="CSV file of domains to check")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    
    args = parser.parse_args()
    
    # Configure logging level based on arguments
    log_level = logging.DEBUG if args.debug else (logging.INFO if args.verbose else logging.WARNING)
    setup_logging(log_level)
    
    logger.info("=== Starting SocGholish Finder ===")
    logger.info(f"Command line arguments: {sys.argv}")
    
    # Set user agent
    ua = args.user_agent or 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36'
    
    try:
        if args.filename:
            logger.info(f"Starting batch scan from file: {args.filename}")
            try:
                with open(args.filename, 'r', encoding='utf-8-sig') as csvFile:
                    raw_file = csv.reader(csvFile)
                    for row in raw_file:
                        if not row or not row[0].strip():
                            continue
                        url = str(row[0]).strip()
                        logger.info(f"Processing URL from file: {url}")
                        try:
                            scan(url, ua)
                        except Exception as e:
                            logger.error(f"Error processing URL {url}: {str(e)}", exc_info=True)
                            continue
            except FileNotFoundError:
                logger.error(f"File not found: {args.filename}")
                return 1
            except Exception as e:
                logger.critical(f"Error reading file {args.filename}: {str(e)}", exc_info=True)
                return 1
                
        elif args.url:
            logger.info(f"Starting scan for URL: {args.url}")
            try:
                scan(args.url, ua)
            except Exception as e:
                logger.critical(f"Error scanning URL {args.url}: {str(e)}", exc_info=True)
                return 1
                
        else:
            logger.error("No URL or filename provided")
            parser.print_help()
            return 1
            
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        return 130  # Standard exit code for Ctrl+C
        
    except Exception as e:
        logger.critical(f"Unexpected error: {str(e)}", exc_info=True)
        return 1
        
    logger.info("=== Scan completed successfully ===")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        logger.critical(f"Unhandled exception: {str(e)}", exc_info=True)
        sys.exit(1)
