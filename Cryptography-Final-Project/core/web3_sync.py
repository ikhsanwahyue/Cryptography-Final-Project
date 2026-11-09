"""
Layer 2: Asynchronous Polygon Amoy Testnet (Chain ID 80002) Web3 Anchoring Worker.
Dispatches a 0 POL self-transaction carrying `data = w3.to_hex(text=evidence_hash)`
in a non-blocking background thread and returns the transaction hash and
PolygonScan Amoy verification URL.
"""

import os
import threading
from dataclasses import dataclass
from typing import Any, Callable, Optional

from eth_account import Account
from web3 import Web3
from web3.providers.rpc import HTTPProvider


@dataclass
class Web3AnchorResult:
    success: bool
    tx_hash: str
    explorer_url: str
    message: str
    is_live_onchain: bool


class Web3SyncWorker:
    """
    Connects to Polygon Amoy Testnet (Chain ID: 80002) via web3.py v6+.
    Anchors SHA-256 evidence hashes on-chain using asynchronous background workers.
    """

    CHAIN_ID = 80002
    EXPLORER_BASE = "https://amoy.polygonscan.com/tx/"
    DEFAULT_RPC = "https://polygon-amoy-bor-rpc.publicnode.com"
    FALLBACK_RPCS = [
        "https://polygon-amoy-bor-rpc.publicnode.com",
        "https://rpc.ankr.com/polygon_amoy",
        "https://polygon-amoy.drpc.org",
        "https://rpc-amoy.polygon.technology",
    ]

    def __init__(
        self,
        rpc_url: Optional[str] = None,
        private_key: Optional[str] = None,
        wallet_address: Optional[str] = None,
        logger_callback: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self.rpc_url = (rpc_url or os.getenv("POLYGON_AMOY_RPC_URL") or self.DEFAULT_RPC).strip()
        self.private_key = (private_key or os.getenv("WALLET_PRIVATE_KEY") or "").strip()
        self.wallet_address = (wallet_address or os.getenv("WALLET_ADDRESS") or "").strip()
        self.logger_callback = logger_callback

    def _log(self, message: str, level: str = "INFO") -> None:
        if self.logger_callback:
            try:
                self.logger_callback(message, level)
            except Exception:
                pass

    @classmethod
    def format_explorer_url(cls, tx_hash: str) -> str:
        clean_hash = tx_hash.strip()
        if not clean_hash.startswith("0x"):
            clean_hash = f"0x{clean_hash}"
        return f"{cls.EXPLORER_BASE}{clean_hash}"

    def _has_configured_wallet(self) -> bool:
        if not self.private_key:
            return False
        stripped = self.private_key.lower().replace("0x", "")
        if not stripped or all(c == "0" for c in stripped) or "your" in stripped:
            return False
        return len(stripped) == 64

    def anchor_evidence_sync(self, evidence_id: str, evidence_hash: str) -> Web3AnchorResult:
        """
        Sends a 0 POL transaction to self on Polygon Amoy Testnet (Chain ID 80002)
        with `data = w3.to_hex(text=evidence_hash)`.
        Includes comprehensive timeout and RPC failure handling.
        """
        if not self._has_configured_wallet():
            msg = (
                "WALLET_PRIVATE_KEY belum dikonfigurasi di .env (menggunakan placeholder). "
                "Bukti diamankan di Layer 1 PoW; setel Private Key Amoy untuk anchor Layer 2 live."
            )
            self._log(msg, "WARN")
            return Web3AnchorResult(
                success=False,
                tx_hash="UNCONFIGURED_WALLET",
                explorer_url="https://amoy.polygonscan.com/",
                message=msg,
                is_live_onchain=False,
            )

        # Prepare list of candidate RPCs (configured RPC first, then fallback list)
        candidate_rpcs = [self.rpc_url] + [u for u in self.FALLBACK_RPCS if u != self.rpc_url]

        w3: Optional[Web3] = None
        connected_rpc = None
        for rpc in candidate_rpcs:
            try:
                headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"}
                candidate_w3 = Web3(HTTPProvider(rpc, request_kwargs={"timeout": 10, "headers": headers}))
                if candidate_w3.is_connected():
                    w3 = candidate_w3
                    connected_rpc = rpc
                    break
            except Exception:
                continue

        if w3 is None or not w3.is_connected():
            err_msg = f"Tidak dapat terhubung ke RPC Polygon Amoy (mencoba {len(candidate_rpcs)} node)."
            self._log(err_msg, "WARN")
            return Web3AnchorResult(
                success=False,
                tx_hash="L2_RPC_OFFLINE",
                explorer_url="https://amoy.polygonscan.com/",
                message=err_msg,
                is_live_onchain=False,
            )

        try:
            account = Account.from_key(self.private_key)
            sender_address = w3.to_checksum_address(account.address)

            nonce = w3.eth.get_transaction_count(sender_address, "pending")
            gas_price = w3.eth.gas_price
            boosted_gas_price = int(gas_price * 1.15)

            payload_hex = w3.to_hex(text=evidence_hash)

            tx_dict: dict[str, Any] = {
                "chainId": self.CHAIN_ID,
                "nonce": nonce,
                "to": sender_address,
                "value": 0,
                "data": payload_hex,
                "gasPrice": boosted_gas_price,
            }

            try:
                estimated_gas = w3.eth.estimate_gas({**tx_dict, "from": sender_address})
                tx_dict["gas"] = max(25000, int(estimated_gas * 1.2))
            except Exception:
                tx_dict["gas"] = 36000

            signed_tx = w3.eth.account.sign_transaction(tx_dict, private_key=self.private_key)
            raw_tx = getattr(signed_tx, "raw_transaction", None) or getattr(
                signed_tx, "rawTransaction"
            )
            tx_hash_bytes = w3.eth.send_raw_transaction(raw_tx)
            tx_hash_hex = w3.to_hex(tx_hash_bytes)
            explorer_url = self.format_explorer_url(tx_hash_hex)

            self._log(
                f"Layer 2 Polygon Amoy Anchor sukses untuk {evidence_id}: {tx_hash_hex}",
                "SUCCESS",
            )
            return Web3AnchorResult(
                success=True,
                tx_hash=tx_hash_hex,
                explorer_url=explorer_url,
                message=f"Anchored on Polygon Amoy Testnet ({tx_hash_hex})",
                is_live_onchain=True,
            )

        except Exception as exc:
            err_msg = f"Layer 2 Polygon Amoy RPC gagal/timeout untuk {evidence_id}: {exc}"
            self._log(err_msg, "WARN")
            return Web3AnchorResult(
                success=False,
                tx_hash="L2_RPC_OFFLINE_OR_INSUFFICIENT_POL",
                explorer_url="https://amoy.polygonscan.com/",
                message=err_msg,
                is_live_onchain=False,
            )

    def anchor_evidence_async(
        self,
        evidence_id: str,
        evidence_hash: str,
        on_complete: Optional[Callable[[str, Web3AnchorResult], None]] = None,
    ) -> threading.Thread:
        """
        Dispatches the Polygon Amoy on-chain transaction asynchronously on a
        background worker thread so the CustomTkinter UI never freezes.
        """

        def _worker() -> None:
            self._log(
                f"Memulai sinkronisasi Layer 2 Polygon Amoy (Chain ID {self.CHAIN_ID}) untuk {evidence_id}...",
                "INFO",
            )
            result = self.anchor_evidence_sync(evidence_id, evidence_hash)
            if on_complete is not None:
                try:
                    on_complete(evidence_id, result)
                except Exception:
                    pass

        thread = threading.Thread(
            target=_worker,
            name=f"LexVault-Web3Sync-{evidence_id}",
            daemon=True,
        )
        thread.start()
        return thread

