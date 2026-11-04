"""
Layer 1: Local Proof-of-Work (PoW) Forensic Blockchain Ledger for LexVault.
Provides immutable local block chaining, SHA-256 Proof-of-Work mining
(target prefix "000"), and deep tamper verification across all blocks.
"""

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class Block:
    index: int
    timestamp: str
    evidence_id: str
    evidence_hash: str
    previous_hash: str
    nonce: int = 0
    hash: str = ""
    layer2_tx_hash: str = "PENDING_SYNC"

    def compute_hash(self) -> str:
        """
        Deterministically computes the SHA-256 hash of the block's canonical fields.
        Note: `layer2_tx_hash` is an external anchor reference added asynchronously
        after L1 block mining, so it is excluded from the L1 PoW header digest.
        """
        block_payload = json.dumps(
            {
                "index": self.index,
                "timestamp": self.timestamp,
                "evidence_id": self.evidence_id,
                "evidence_hash": self.evidence_hash,
                "previous_hash": self.previous_hash,
                "nonce": self.nonce,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(block_payload.encode("utf-8")).hexdigest()

    def mine(self, difficulty_prefix: str = "000") -> str:
        """
        Executes Proof-of-Work mining until `self.hash.startswith(difficulty_prefix)`.
        """
        self.nonce = 0
        computed = self.compute_hash()
        while not computed.startswith(difficulty_prefix):
            self.nonce += 1
            computed = self.compute_hash()
        self.hash = computed
        return self.hash

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "evidence_id": self.evidence_id,
            "evidence_hash": self.evidence_hash,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash,
            "layer2_tx_hash": self.layer2_tx_hash,
        }


class LocalBlockchain:
    """
    Layer 1 Chain of Custody Ledger with Proof-of-Work ("000") and database synchronization.
    """

    DIFFICULTY_PREFIX = "000"

    def __init__(self, db_manager: Optional[Any] = None) -> None:
        self.db_manager = db_manager
        self.chain: List[Block] = []
        self.reload_from_db()

    def reload_from_db(self) -> None:
        """Loads stored audit blocks from DatabaseManager, or mines Genesis block if empty."""
        self.chain.clear()
        if self.db_manager is not None:
            stored = self.db_manager.load_audit_blocks()
            for row in stored:
                blk = Block(
                    index=int(row["block_index"]),
                    timestamp=str(row["timestamp"]),
                    evidence_id=str(row["evidence_id"]),
                    evidence_hash=str(row["evidence_hash"]),
                    previous_hash=str(row["previous_hash"]),
                    nonce=int(row["nonce"]),
                    hash=str(row["block_hash"]),
                    layer2_tx_hash=str(row.get("layer2_tx_hash") or "PENDING_SYNC"),
                )
                self.chain.append(blk)

        if not self.chain:
            self._create_genesis_block()

    def _create_genesis_block(self) -> Block:
        genesis = Block(
            index=0,
            timestamp="2026-01-01T00:00:00+00:00",
            evidence_id="GENESIS-ISO27037-ANCHOR",
            evidence_hash=hashlib.sha256(b"LEXVAULT_FORENSIC_GENESIS_BLOCK").hexdigest(),
            previous_hash="0" * 64,
            nonce=0,
            layer2_tx_hash="GENESIS_ROOT",
        )
        genesis.mine(self.DIFFICULTY_PREFIX)
        self.chain.append(genesis)
        if self.db_manager is not None:
            self.db_manager.save_audit_block(genesis.to_dict())
        return genesis

    @property
    def latest_block(self) -> Block:
        if not self.chain:
            return self._create_genesis_block()
        return self.chain[-1]

    def add_evidence_block(
        self,
        evidence_id: str,
        evidence_hash: str,
        layer2_tx_hash: str = "PENDING_SYNC",
    ) -> Block:
        """
        Creates a new block linked to `latest_block.hash`, mines it with PoW ("000"),
        appends it to the chain, and persists it to the database.
        """
        prev_block = self.latest_block
        new_block = Block(
            index=prev_block.index + 1,
            timestamp=datetime.now(timezone.utc).isoformat(),
            evidence_id=evidence_id,
            evidence_hash=evidence_hash,
            previous_hash=prev_block.hash,
            nonce=0,
            layer2_tx_hash=layer2_tx_hash,
        )
        new_block.mine(self.DIFFICULTY_PREFIX)
        self.chain.append(new_block)
        if self.db_manager is not None:
            self.db_manager.save_audit_block(new_block.to_dict())
        return new_block

    def is_chain_valid(self) -> Tuple[bool, List[str], List[int]]:
        """
        Audits the entire local ledger from Genesis (index 0) to the latest block.
        Reloads from DB first so any external/manual SQLite edits are immediately caught.
        Returns: (is_valid, audit_messages, compromised_block_indices)
        """
        if self.db_manager is not None:
            self.reload_from_db()

        issues: List[str] = []
        compromised_indices: List[int] = []

        if not self.chain:
            return False, ["Chain kosong: Blok Genesis hilang!"], [0]

        for i, current in enumerate(self.chain):
            recalculated_hash = current.compute_hash()

            # 1. Verify stored block hash matches recalculated SHA-256
            if current.hash != recalculated_hash:
                issues.append(
                    f"[BREACH BLOK #{current.index}] Hash blok tidak cocok! "
                    f"Tersimpan: {current.hash[:16]}... vs Kalkulasi Ulang: {recalculated_hash[:16]}... "
                    f"(Bukti '{current.evidence_id}' telah dimodifikasi secara ilegal)."
                )
                compromised_indices.append(current.index)

            # 2. Verify Proof-of-Work target ("000")
            if not current.hash.startswith(self.DIFFICULTY_PREFIX) or not recalculated_hash.startswith(
                self.DIFFICULTY_PREFIX
            ):
                issues.append(
                    f"[BREACH BLOK #{current.index}] Proof-of-Work ('{self.DIFFICULTY_PREFIX}') tidak valid!"
                )
                if current.index not in compromised_indices:
                    compromised_indices.append(current.index)

            # 3. Verify cryptographic link to previous block
            if i > 0:
                prev = self.chain[i - 1]
                prev_recalculated = prev.compute_hash()
                if current.previous_hash != prev.hash or current.previous_hash != prev_recalculated:
                    issues.append(
                        f"[CHAIN BROKEN PADA BLOK #{current.index}] previous_hash ({current.previous_hash[:16]}...) "
                        f"putus dari Blok #{prev.index} ({prev_recalculated[:16]}...)."
                    )
                    if current.index not in compromised_indices:
                        compromised_indices.append(current.index)

        if issues:
            return False, issues, compromised_indices

        return (
            True,
            [
                f"INTEGRITAS TERVERIFIKASI: Seluruh {len(self.chain)} blok valid, "
                f"Proof-of-Work ('{self.DIFFICULTY_PREFIX}') utuh, dan rantai hash berkesinambungan."
            ],
            [],
        )

