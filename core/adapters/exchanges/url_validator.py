"""
URL 验证器 - 防止 SSRF (Server-Side Request Forgery) 攻击

提供安全的 URL 验证和白名单检查功能
"""

import re
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)


# 定义每个交易所的允许 URL 白名单
ALLOWED_URLS = {
    'lighter': {
        'mainnet': [
            'https://mainnet.zklighter.elliot.ai',
            'https://api.zklighter.elliot.ai'
        ],
        'testnet': [
            'https://testnet.zklighter.elliot.ai',
            'https://testnet-api.zklighter.elliot.ai'
        ],
        'ws_mainnet': [
            'wss://mainnet.zklighter.elliot.ai',
            'wss://mainnet.zklighter.elliot.ai/stream'
        ],
        'ws_testnet': [
            'wss://testnet.zklighter.elliot.ai',
            'wss://testnet.zklighter.elliot.ai/stream'
        ]
    },
    'backpack': {
        'mainnet': [
            'https://api.backpack.exchange',
            'https://api.backpack.exchange/'
        ],
        'testnet': [
            'https://api.backpack.exchange'  # Backpack 使用相同的 API 端点
        ],
        'ws_mainnet': [
            'wss://ws.backpack.exchange',
            'wss://ws.backpack.exchange/'
        ],
        'ws_testnet': [
            'wss://ws.backpack.exchange'
        ]
    },
    'binance': {
        'mainnet': [
            'https://fapi.binance.com',
            'https://api.binance.com'
        ],
        'testnet': [
            'https://testnet.binancefuture.com',
            'https://testnet.binance.vision'
        ],
        'ws_mainnet': [
            'wss://fstream.binance.com',
            'wss://stream.binance.com:9443'
        ],
        'ws_testnet': [
            'wss://stream.binancefuture.com'
        ]
    },
    'okx': {
        'mainnet': [
            'https://www.okx.com',
            'https://okx.com',
            'https://api.okx.com'
        ],
        'testnet': [
            'https://www.okx.com',  # OKX 使用演练账户
            'https://okx.com'
        ],
        'ws_mainnet': [
            'wss://ws.okx.com:8443',
            'wss://ws.okx.com:8443/ws/v5/public',
            'wss://ws.okx.com:8443/ws/v5/private'
        ],
        'ws_testnet': [
            'wss://wspap.okx.com:8443',
            'wss://wspap.okx.com:8443/ws/v5/public',
            'wss://wspap.okx.com:8443/ws/v5/private'
        ]
    },
    'edgex': {
        'mainnet': [
            'https://api.edgex.exchange',
            'https://edgex.exchange'
        ],
        'testnet': [
            'https://api.edgex.exchange',
            'https://edgex.exchange'
        ],
        'ws_mainnet': [
            'wss://ws.edgex.exchange'
        ],
        'ws_testnet': [
            'wss://ws.edgex.exchange'
        ]
    },
    'hyperliquid': {
        'mainnet': [
            'https://api.hyperliquid.xyz',
            'https://hyperliquid.xyz'
        ],
        'testnet': [
            'https://testnet.hyperliquid.xyz',
            'https://api-testnet.hyperliquid.xyz'
        ],
        'ws_mainnet': [
            'wss://api.hyperliquid.xyz/ws'
        ],
        'ws_testnet': [
            'wss://testnet.hyperliquid.xyz/ws'
        ]
    }
}


class URLValidator:
    """URL 验证器"""

    @staticmethod
    def is_allowed_url(exchange_name: str, url: str, is_testnet: bool = False, is_websocket: bool = False) -> bool:
        """
        检查 URL 是否在白名单中
        
        Args:
            exchange_name: 交易所名称 (lowercase)
            url: 要验证的 URL
            is_testnet: 是否使用测试网
            is_websocket: 是否是 WebSocket URL
            
        Returns:
            如果 URL 在白名单中返回 True，否则返回 False
        """
        if not url:
            return False
            
        # 获取交易所的白名单
        exchange_whitelist = ALLOWED_URLS.get(exchange_name.lower())
        if not exchange_whitelist:
            logger.warning(f"未知的交易所: {exchange_name}")
            return False
        
        # 选择合适的白名单类型
        if is_websocket:
            whitelist_key = f"ws_{'testnet' if is_testnet else 'mainnet'}"
        else:
            whitelist_key = 'testnet' if is_testnet else 'mainnet'
        
        allowed_urls = exchange_whitelist.get(whitelist_key, [])
        
        # 规范化 URL（移除尾部斜杠并转换为小写）
        normalized_url = url.rstrip('/').lower()
        
        # 检查精确匹配或前缀匹配
        for allowed_url in allowed_urls:
            allowed_normalized = allowed_url.rstrip('/').lower()
            if normalized_url == allowed_normalized or normalized_url.startswith(allowed_normalized + '/'):
                return True
        
        return False

    @staticmethod
    def validate_url_safety(url: str) -> bool:
        """
        执行通用的 URL 安全检查
        
        Args:
            url: 要验证的 URL
            
        Returns:
            如果 URL 安全返回 True，否则返回 False
        """
        if not url:
            return False
        
        try:
            parsed = urlparse(url)
            
            # 1. 检查协议 - 只允许 http/https/ws/wss
            if parsed.scheme not in ('http', 'https', 'ws', 'wss'):
                logger.warning(f"不允许的协议: {parsed.scheme}")
                return False
            
            # 2. 检查主机名 - 拒绝私有 IP 和元数据端点
            hostname = parsed.hostname
            if not hostname:
                return False
            
            hostname_lower = hostname.lower()
            
            # 禁止的主机模式
            forbidden_patterns = [
                r'^127\.',           # localhost
                r'^169\.254\.',      # AWS IMDSv1/v2
                r'^::1$',            # IPv6 localhost
                r'^fe80:',           # IPv6 link-local
                r'^10\.',            # 私有 IP
                r'^172\.(1[6-9]|2[0-9]|3[01])\.',  # 私有 IP
                r'^192\.168\.',      # 私有 IP
                r'localhost',        # localhost
                r'metadata',         # 元数据服务
                r'docker\.sock',     # Docker socket
                r'redis',            # 可能的 Redis 实例
                r'\.internal$',      # 内部 IP
            ]
            
            for pattern in forbidden_patterns:
                if re.search(pattern, hostname_lower, re.IGNORECASE):
                    logger.warning(f"禁止的主机名: {hostname}")
                    return False
            
            # 3. 检查端口 - 拒绝常见的危险端口
            if parsed.port:
                dangerous_ports = {
                    22,    # SSH
                    23,    # Telnet
                    3306,  # MySQL
                    5432,  # PostgreSQL
                    6379,  # Redis
                    27017, # MongoDB
                    8080,  # 常见内部服务
                }
                if parsed.port in dangerous_ports:
                    logger.warning(f"危险端口: {parsed.port}")
                    return False
            
            return True
            
        except Exception as e:
            logger.warning(f"URL 解析错误: {e}")
            return False

    @staticmethod
    def sanitize_url(url: str) -> str:
        """
        清理 URL - 移除查询参数和片段
        
        Args:
            url: 要清理的 URL
            
        Returns:
            清理后的 URL
        """
        if not url:
            return ""
        
        try:
            parsed = urlparse(url)
            # 只保留 scheme, netloc, path
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip('/')
        except Exception as e:
            logger.warning(f"URL 清理错误: {e}")
            return url

    @staticmethod
    def get_allowed_base_urls(exchange_name: str, is_testnet: bool = False) -> List[str]:
        """
        获取交易所允许的 base URL 列表
        
        Args:
            exchange_name: 交易所名称
            is_testnet: 是否使用测试网
            
        Returns:
            允许的 URL 列表
        """
        exchange_whitelist = ALLOWED_URLS.get(exchange_name.lower())
        if not exchange_whitelist:
            return []
        
        whitelist_key = 'testnet' if is_testnet else 'mainnet'
        return exchange_whitelist.get(whitelist_key, [])

    @staticmethod
    def get_allowed_ws_urls(exchange_name: str, is_testnet: bool = False) -> List[str]:
        """
        获取交易所允许的 WebSocket URL 列表
        
        Args:
            exchange_name: 交易所名称
            is_testnet: 是否使用测试网
            
        Returns:
            允许的 WebSocket URL 列表
        """
        exchange_whitelist = ALLOWED_URLS.get(exchange_name.lower())
        if not exchange_whitelist:
            return []
        
        whitelist_key = f"ws_{'testnet' if is_testnet else 'mainnet'}"
        return exchange_whitelist.get(whitelist_key, [])
