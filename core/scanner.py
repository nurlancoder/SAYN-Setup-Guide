"""
SAYN Core Scanner Engine
Enhanced scanning engine with better error handling and retry logic
"""
import asyncio
import aiohttp
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor
import time
import logging
from aiohttp import ClientError, ClientTimeout
import ssl
import certifi

class ScannerEngine:
    """Enhanced scanning engine with better error handling and retry logic"""
    
    def __init__(self):
        self.version = "2.1.0"
        self.executor = ThreadPoolExecutor(max_workers=20)
        self.logger = logging.getLogger('SAYN.scanner')
        self.default_headers = {
            'User-Agent': 'SAYN Security Scanner v2.1',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        self.session = None

    async def __aenter__(self):
        """Async context manager entry"""
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        connector = aiohttp.TCPConnector(
            force_close=True, 
            enable_cleanup_closed=True,
            ssl=ssl_context,
            limit=100,
            limit_per_host=30
        )
        
        self.session = aiohttp.ClientSession(
            timeout=ClientTimeout(total=30, connect=10),
            headers=self.default_headers,
            connector=connector
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session and not self.session.closed:
            await self.session.close()

    async def make_request(self, url: str, method: str = 'GET', 
                         retries: int = 3, **kwargs) -> Dict[str, Any]:
        """Make async HTTP request with retry logic and enhanced error handling"""
        last_error = None
        response_time = 0
        
        for attempt in range(1, retries + 1):
            try:
                start_time = time.time()
                
                if not self.session or self.session.closed:
                    ssl_context = ssl.create_default_context(cafile=certifi.where())
                    connector = aiohttp.TCPConnector(
                        force_close=True, 
                        enable_cleanup_closed=True,
                        ssl=ssl_context
                    )
                    self.session = aiohttp.ClientSession(
                        timeout=ClientTimeout(total=30, connect=10),
                        headers=self.default_headers,
                        connector=connector
                    )
                
                headers = kwargs.pop('headers', {})
                final_headers = {**self.default_headers, **headers}
                
                async with self.session.request(
                    method, url, headers=final_headers, 
                    allow_redirects=True, **kwargs
                ) as response:
                    content = await response.text()
                    response_time = time.time() - start_time
                    
                    return {
                        'url': str(response.url),
                        'status_code': response.status,
                        'headers': dict(response.headers),
                        'content': content,
                        'cookies': {c.key: c.value for c in response.cookies.values()},
                        'response_time': response_time,
                        'attempt': attempt,
                        'error': None,
                        'ssl_info': self._get_ssl_info(response.connection.transport) if hasattr(response.connection, 'transport') else None
                    }
                    
            except ClientError as e:
                last_error = str(e)
                self.logger.warning(f"Attempt {attempt} failed for {url}: {str(e)}")
                if attempt < retries:
                    await asyncio.sleep(attempt * 0.5)  
                continue
            except Exception as e:
                last_error = str(e)
                self.logger.error(f"Unexpected error scanning {url}: {str(e)}")
                break
        
        return {
            'url': url,
            'status_code': 0,
            'headers': {},
            'content': '',
            'cookies': {},
            'response_time': response_time,
            'attempt': attempt,
            'error': last_error,
            'ssl_info': None
        }

    def _get_ssl_info(self, transport) -> Optional[Dict]:
        """Extract SSL information from transport"""
        try:
            if hasattr(transport, 'get_extra_info'):
                ssl_object = transport.get_extra_info('ssl_object')
                if ssl_object:
                    return {
                        'version': ssl_object.version(),
                        'cipher': ssl_object.cipher(),
                        'compression': ssl_object.compression(),
                        'verify_mode': ssl_object.verify_mode
                    }
        except Exception:
            pass
        return None

    async def scan_multiple_urls(self, urls: List[str], max_concurrent: int = 10) -> List[Dict]:
        """Scan multiple URLs concurrently with improved rate limiting"""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def scan_with_semaphore(url):
            async with semaphore:
                start_time = time.time()
                result = await self.make_request(url)
                result['response_time'] = time.time() - start_time
                return result
        
        batch_size = 50
        all_results = []
        
        for i in range(0, len(urls), batch_size):
            batch = urls[i:i + batch_size]
            tasks = [scan_with_semaphore(url) for url in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in batch_results:
                if not isinstance(result, Exception):
                    all_results.append(result)
                else:
                    self.logger.error(f"Error processing URL batch: {str(result)}")
            
            await asyncio.sleep(0.1)
        
        return all_results

    async def scan_with_custom_headers(self, url: str, headers: Dict[str, str]) -> Dict[str, Any]:
        """Scan with custom headers for specific vulnerability testing"""
        return await self.make_request(url, headers=headers)

    async def scan_with_payloads(self, url: str, payloads: List[str], param: str = 'q') -> List[Dict[str, Any]]:
        """Scan URL with multiple payloads for vulnerability testing"""
        results = []
        for payload in payloads:
            test_url = f"{url}?{param}={payload}"
            result = await self.make_request(test_url)
            result['payload'] = payload
            result['parameter'] = param
            results.append(result)
        return results

    def run_sync_scan(self, func, *args, **kwargs):
        """Run synchronous scanning function in thread pool"""
        loop = asyncio.get_event_loop()
        return loop.run_in_executor(self.executor, func, *args, **kwargs)

    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on the scanner engine"""
        try:
            test_url = "https://httpbin.org/get"
            result = await self.make_request(test_url)
            return {
                'status': 'healthy' if result['status_code'] == 200 else 'unhealthy',
                'response_time': result['response_time'],
                'error': result.get('error')
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
