from hashlib import sha256

from eth_typing.encoding import HexStr
from eth_typing.evm import HexAddress
from eth_utils.hexadecimal import remove_0x_prefix
from web3.main import Web3


def compute_did_from_data_nft_address_and_chain_id(
    data_nft_address: HexAddress, chain_id: int
) -> HexStr:
    """Return a DID calculated from the data NFT address and chain ID.
    See for details: https://github.com/oceanprotocol/docs/blob/v4main/content/concepts/did-ddo.md#did
    """
    return "did:op:" + remove_0x_prefix(
        Web3.toHex(sha256((data_nft_address + str(chain_id)).encode("utf-8")).digest())
    )
