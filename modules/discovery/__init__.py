"""
Discovery — expand attack surface via SPA routes and Wayback Machine.
"""

from modules.discovery.robots import discover_robots_and_sitemap, parse_robots, parse_sitemap_locs
from modules.discovery.spa import crawl_spa_routes, extract_routes_from_js, instantiate_route_params
from modules.discovery.wayback import get_wayback_endpoints, get_wayback_js_urls, fetch_wayback_js

__all__ = [
    "crawl_spa_routes", "extract_routes_from_js", "instantiate_route_params",
    "get_wayback_endpoints", "get_wayback_js_urls", "fetch_wayback_js",
    "discover_robots_and_sitemap", "parse_robots", "parse_sitemap_locs",
]
