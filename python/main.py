import json
import requests
from typing import Annotated, Any, Dict, Generic, List, Optional, TypeVar, Union

import time
from pydantic import Field
from pydantic.generics import GenericModel
from substrateinterface import keypair


# Define a type variable
T = TypeVar("T")


class EpistulaRequest(GenericModel, Generic[T]):
    data: T
    nonce: int = Field(
        title="Nonce", description="Unix timestamp of when request was sent"
    )
    signed_by: str = Field(title="Signed By", description="Hotkey of sender / signer")
    signed_for: str = Field(
        title="Signed For", description="Hotkey of intended receiver"
    )


def generate_body(
    data: Union[Dict[Any, Any], List[Any]],
    sender_hotkey: str,
    receiver_hotkey: Optional[str] = None
) -> Dict[str, Any]:
    return {
        "data": data,
        "nonce": time.time_ns(),
        "signed_by": sender_hotkey,
        "signed_for": receiver_hotkey,
        "version": 1,
    }


def generate_header(
    hotkey: keypair.Keypair, body: Union[Dict[Any, Any], List[Any]]
) -> Dict[str, Any]:
    return {"Body-Signature": "0x" + hotkey.sign(json.dumps(body)).hex()}


def verify_signature(
    signature, body: bytes, nonce, sender, now
) -> Optional[Annotated[str, "Error Message"]]:
    if not isinstance(signature, str):
        return "Invalid Signature"
    if not isinstance(nonce, int):
        return "Invalid Nonce"
    if not isinstance(sender, str):
        return "Invalid Sender key"
    if not isinstance(body, bytes):
        return "Body is not of type bytes"
    ALLOWED_DELTA_NS = 5 * 1000000000
    keys = keypair.Keypair(ss58_address=sender)
    if nonce + ALLOWED_DELTA_NS < now:
        return "Request is too stale"
    verified = keys.verify(body, signature)
    if not verified:
        return "Signature Mismatch"
    return None

keys = keypair.Keypair.create_from_mnemonic("mosquito same host random label hover weather sustain elevator mobile uncle improve")
body = generate_body({"hello": "world"}, keys.ss58_address)
headers = generate_header(keys, body)
requests.post(
    url=f"http://localhost:4000",
    headers=headers,
    json=body,
)
