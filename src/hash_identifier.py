import re 
from dataclasses import dataclass 
from enum import Enum
from typing import List



class Confidence(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Hashcandidate: 
    name:str
    confidence: Confidence
    description: str

class HashIdentifier: 
    def __init__(self):
        #High confidence prefix rules
        self.prefix_rules = [
            (
                            r"^\$argon2(i|d|id)\$v=\d+\$m=\d+,t=\d+,p=\d+\$",
                            "Argon2",
                            "Modern key derivation function (PHC format)",
                        ),
                        (
                            r"^\$2[abxy]\$\d{2}\$",
                            "Bcrypt",
                            "Blowfish-based password hash",
                        ),
                        (
                            r"^\$6\$",
                            "SHA-512 Crypt",
                            "Linux /etc/shadow password hash",
                        ),
                        (
                            r"^\$5\$",
                            "SHA-256 Crypt",
                            "Linux /etc/shadow password hash",
                        ),
                        (
                            r"^\$apr1\$",
                            "Apache MD5",
                            "Apache htpasswd format",
                        ),
                        (
                            r"^pbkdf2_sha256\$",
                            "PBKDF2-SHA256",
                            "Django default password hash",
                        ),
                        (
                            r"^\{SSHA\}",
                            "Salted SHA-1",
                            "LDAP directory service hash",
                        ),
        ]

        #Medium/Low confidence lookup table by hex length\
        self.hex_length_map = {
            32: [
                ("MD5", Confidence.MEDIUM, "Common 128-bit hash / checksum"),
                ("NTLM", Confidence.LOW, "Windows NT LAN Manager hash"),
                ("MD4", Confidence.LOW, "Legacy 128-bit hash"),
            ],
            40: [
                ("SHA-1", Confidence.MEDIUM, "Common 160-bit hash"),
                ("RIPEMD-160", Confidence.LOW, "160-bit cryptographic hash"),
            ],
            56: [
                ("SHA-224", Confidence.MEDIUM, "224-bit SHA-2 family hash"),
                ("SHA3-224", Confidence.LOW, "224-bit SHA-3 family hash"),
            ],
            64: [
                ("SHA-256", Confidence.MEDIUM, "Standard 256-bit SHA-2 family hash"),
                ("SHA3-256", Confidence.LOW, "256-bit SHA-3 family hash"),
                ("BLAKE2s-256", Confidence.LOW, "256-bit fast hashing algorithm"),
            ],
            96: [
                ("SHA-384", Confidence.MEDIUM, "384-bit SHA-2 family hash"),
                ("SHA3-384", Confidence.LOW, "384-bit SHA-3 family hash"),
            ],
            128: [
                ("SHA-512", Confidence.MEDIUM, "Standard 512-bit SHA-2 family hash"),
                ("SHA3-512", Confidence.LOW, "512-bit SHA-3 family hash"),
                ("BLAKE2b-512", Confidence.LOW, "512-bit fast hashing algorithm"),
            ],
        }
    def identify(self, hash_string:str) -> List[Hashcandidate]:
        clean_hash = hash_string.strip() 
        candidates: List[Hashcandidate] = []

        for pattern, name, desc in self.prefix_rules:
            if re.search(pattern, clean_hash):
                candidates.append(
                    Hashcandidate(
                        name = name,
                        confidence= Confidence.HIGH,
                        description=desc,
                    )
                )
                return candidates

        is_hex = bool(re.match(r"^[a-fA-F0-9]+$", clean_hash))

        if is_hex: 
            length = len(clean_hash)
            if length in self.hex_length_map:
                for name, conf, desc in self.hex_length_map[length]:
                    candidates.append(
                    Hashcandidate(
                        name = name,
                        confidence= Confidence.HIGH,
                        description=desc,
                        )
                    )   
        return candidates