"""
Controlled Web Crawler for KRYPT CLI (inspired by Photon & TorBot).
Performs asynchronous, queue-based (BFS) discovery with strict scope and rate control.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from krypt.core.config import config
from krypt.core.http import HttpClient
from krypt.core.logger import audit_log, logger
from krypt.crawler.parser import HtmlParser
from krypt.crawler.scripts import ScriptAnalyzer
from krypt.database.db import db
from krypt.safety.scope import ScopeEngine


@dataclass
class CrawlResult:
    target_url: str
    total_processed: int = 0
    discovered_urls: Set[str] = field(default_factory=set)
    processed_urls: Set[str] = field(default_factory=set)
    failed_urls: Set[str] = field(default_factory=set)
    internal_urls: Set[str] = field(default_factory=set)
    external_urls: Set[str] = field(default_factory=set)
    scripts: Set[str] = field(default_factory=set)
    endpoints: Set[str] = field(default_factory=set)
    parameters: Set[str] = field(default_factory=set)
    forms_count: int = 0


class Crawler:
    """BFS Async Web Crawler with rate limiting and depth bounds."""

    def __init__(
        self,
        max_depth: Optional[int] = None,
        max_pages: Optional[int] = None,
        rate_limit: Optional[float] = None,
        threads: Optional[int] = None,
        timeout: Optional[float] = None,
        same_origin_only: bool = True
    ):
        self.max_depth = max_depth if max_depth is not None else int(config.get("crawler.max_depth", 3))
        self.max_pages = max_pages if max_pages is not None else int(config.get("crawler.max_pages", 50))
        self.rate_limit = rate_limit if rate_limit is not None else float(config.get("crawler.rate", 10.0))
        self.concurrency = threads if threads is not None else int(config.get("crawler.threads", 5))
        self.timeout = timeout if timeout is not None else float(config.get("crawler.timeout", 10.0))
        self.same_origin_only = same_origin_only

        self.http = HttpClient(timeout=self.timeout, rate_limit=self.rate_limit)

    def _is_same_origin(self, base_host: str, url: str) -> bool:
        """Check if URL belongs to target host."""
        parsed = urlparse(url)
        return parsed.hostname == base_host or (parsed.hostname is None)

    async def crawl(self, target: str) -> CrawlResult:
        """Execute BFS crawl."""
        canonical_url, host, port, scheme = ScopeEngine.normalize_target(target)
        ScopeEngine.check_scope(target, is_active_assessment=False, allow_passive=True)

        result = CrawlResult(target_url=canonical_url)
        
        queue: asyncio.Queue[Tuple[str, int]] = asyncio.Queue()
        await queue.put((canonical_url, 0))
        result.discovered_urls.add(canonical_url)
        result.internal_urls.add(canonical_url)

        semaphore = asyncio.Semaphore(self.concurrency)
        audit_log("CRAWL_START", canonical_url, "STARTED", f"Depth={self.max_depth}, MaxPages={self.max_pages}")

        async def worker():
            while not queue.empty() and len(result.processed_urls) < self.max_pages:
                try:
                    current_url, depth = await asyncio.wait_for(queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    break

                if current_url in result.processed_urls:
                    queue.task_done()
                    continue

                if depth > self.max_depth:
                    queue.task_done()
                    continue

                async with semaphore:
                    try:
                        resp = await self.http.get(current_url)
                        result.processed_urls.add(current_url)
                        result.total_processed += 1

                        if resp and resp.status_code == 200:
                            content_type = resp.headers.get("content-type", "")
                            
                            # Parse HTML
                            if "text/html" in content_type or not content_type:
                                parsed_page = HtmlParser.parse(current_url, resp.text)
                                result.forms_count += len(parsed_page.forms)

                                # Track endpoints and params
                                for ep in parsed_page.endpoints:
                                    full_ep = urljoin(canonical_url, ep)
                                    result.endpoints.add(full_ep)
                                    db.add_endpoint(
                                        target_url=canonical_url,
                                        method="GET",
                                        url=full_ep,
                                        path=ep,
                                        discovered_from=f"crawl:{current_url}",
                                        confidence="HIGH"
                                    )

                                for param in parsed_page.parameters:
                                    result.parameters.add(param)

                                for s_url in parsed_page.scripts:
                                    result.scripts.add(s_url)

                                # Add new links to queue if within depth
                                for link in parsed_page.links:
                                    is_internal = self._is_same_origin(host, link)
                                    if is_internal:
                                        result.internal_urls.add(link)
                                        if link not in result.discovered_urls and len(result.discovered_urls) < (self.max_pages * 2):
                                            result.discovered_urls.add(link)
                                            if depth + 1 <= self.max_depth:
                                                await queue.put((link, depth + 1))
                                    else:
                                        result.external_urls.add(link)

                                # Register endpoint
                                parsed_curr = urlparse(current_url)
                                db.add_endpoint(
                                    target_url=canonical_url,
                                    method="GET",
                                    url=current_url,
                                    path=parsed_curr.path or "/",
                                    parameters=",".join(parsed_page.parameters),
                                    content_type=content_type,
                                    discovered_from="crawler",
                                    confidence="HIGH"
                                )
                        else:
                            result.failed_urls.add(current_url)
                    except Exception as e:
                        logger.debug(f"Crawler error on {current_url}: {e}")
                        result.failed_urls.add(current_url)
                    finally:
                        queue.task_done()

        # Run concurrent workers
        workers = [asyncio.create_task(worker()) for _ in range(self.concurrency)]
        await asyncio.gather(*workers, return_exceptions=True)
        await self.http.close()

        audit_log("CRAWL_COMPLETE", canonical_url, "COMPLETED", f"Processed={result.total_processed}, Endpoints={len(result.endpoints)}")
        return result
