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
from db import get_db_session, Source, Indicator


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

def FindSocGholish(scripts, source_url):
    potential_sg = []
    session = get_db_session()
    
    try:
        source, _ = Source.get_or_create(session, url=source_url)
        
        for s in scripts:
            script_url, script_content = s
            if not script_content:
                continue
                
            for i, indicator in enumerate(indicators):
                if isinstance(indicator, tuple):
                    for regex in indicator:
                        if re.search(regex, script_content, re.I):
                            Indicator.create_from_snippet(
                                session=session,
                                source=source,
                                snippet_text=script_content,
                                detection_method=f"indicator_{i}",
                                stage=1
                            )
                else:
                    if re.search(indicator, script_content, re.I):
                        Indicator.create_from_snippet(
                            session=session,
                            source=source,
                            snippet_text=script_content,
                            detection_method=f"indicator_{i}",
                            stage=1
                        )
        
        session.commit()
        return potential_sg
        
    except Exception as e:
        session.rollback()
        logger.error(f"Database error: {str(e)}", exc_info=True)
        return []
    finally:
        session.close()

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

def scan(url, ua, mark_benign=False):
    """Scan a website for SocGholish indicators.
    
    Args:
        url (str): The URL to scan
        ua (str): User-Agent string to use for requests
        mark_benign (bool): If True, mark the site as benign in the database
        
    Returns:
        bool: True if indicators were found, False otherwise
    """
    logger.info(f"Scanning website {url}")
    session = get_db_session()
    hit = False
    
    try:
        # Get or create source and update last_checked
        source, _ = Source.get_or_create(session, url=url)
        source.last_checked = datetime.utcnow()
        
        if mark_benign:
            logger.info(f"Marking {url} as benign")
            source.is_benign = True
            session.commit()
            return False
            
        # If site is marked as benign, skip scanning
        if source.is_benign is True:
            logger.debug(f"Skipping known benign site: {url}")
            return False
            
        scripts = ParseWebsite(url, ua)
        sg = FindSocGholish(scripts, url)
        
        if not sg:  # No indicators found
            logger.debug(f"No indicators found on {url}")
            source.is_benign = True  # Mark as benign if no indicators found
            session.commit()
            return False
            
        # Process found indicators
        stage2 = []
        for e in sg:
            logger.warning(f"Found potential SocGholish on {e[0][0]} (matched {e[1]} out of {len(indicators)} indicators)")
            stage2_url = urljoin(url, Stage2Url(e[0]))
            if "report" in stage2_url:
                stage2.append(stage2_url)
                
                # Check stage 2 URLs
                try:
                    response = GetWebsite(
                        urljoin(url, stage2_url),
                        headers={
                            'Host': url.split('/')[2],
                            'User-Agent': ua,
                            'referer': url
                        }
                    )
                    s2url = Stage2Url(response.content)
                    if s2url is not None:
                        logger.warning(f"Found stage 2 URL: {s2url}")
                        hit = True
                except Exception as e:
                    logger.error(f"Error checking stage 2 URL {stage2_url}: {str(e)}")
        
        # Check for suspicious script URLs
        for script in scripts:
            script_url = script[0] if isinstance(script, (list, tuple)) else script
            if re.match(r"[A-Za-z0-9]{32,}", script_url.split("/")[-1]) is not None:
                try:
                    r = GetWebsite(script_url, headers={'User-Agent': ua})
                    if r.content == b'':
                        logger.warning(f"Empty response from suspicious script: {script_url}")
                        hit = True
                except Exception as e:
                    logger.error(f"Error checking script {script_url}: {str(e)}")
        
        # Update source status based on findings
        source.is_benign = not (bool(sg) or hit)
        session.commit()
        
        # Log findings
        if stage2:
            logger.warning(f"Found {len(stage2)} potential stage 2 URLs")
            for u in stage2:
                logger.warning(f"Stage 2 URL: {u}")
        
        if hit:
            logger.warning(f"Found potential SocGholish indicators on {url}")
        else:
            logger.info(f"No SocGholish payload found on {url}")
            
        return hit or bool(sg)
        
    except Exception as e:
        logger.error(f"Error scanning {url}: {str(e)}", exc_info=True)
        session.rollback()
        return False
    finally:
        session.close()

def main():
    parser = argparse.ArgumentParser(description='SocGholish finder')
    parser.add_argument("-url", type=str, help="URL to check")
    parser.add_argument("-ua", "--user-agent", type=str, 
                      default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                      help="Specify User-Agent to use with the request")
    parser.add_argument("-f", "--filename", type=str, help="CSV file of domains to check")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--mark-benign", action="store_true", 
                       help="Mark the specified URL as benign in the database")
    
    args = parser.parse_args()

    # Set up logging
    log_level = logging.DEBUG if args.debug else (logging.INFO if args.verbose else logging.WARNING)
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.handlers.RotatingFileHandler(
                'socgholish_scan.log',
                maxBytes=5*1024*1024,  # 5MB
                backupCount=3
            )
        ]
    )

    if args.url:
        scan(args.url, args.user_agent, mark_benign=args.mark_benign)
    elif args.filename:
        # Process CSV file
        try:
            with open(args.filename, 'r') as f:
                reader = csv.reader(f)
                for row in reader:
                    if row:  # Skip empty lines
                        url = row[0].strip()
                        if url:  # Skip empty URLs
                            scan(url, args.user_agent)
        except Exception as e:
            logger.error(f"Error processing file {args.filename}: {str(e)}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()