from ocean_utils.aquarius.aquarius import Aquarius

from ocean_lib.models.data_token import DataToken


def get_asset_from_metadatastore(metadata_url, document_id):
    aqua = Aquarius(metadata_url)
    return aqua.get_asset_ddo(document_id)


def get_asset_for_data_token(token_address, document_id):
    return get_asset_from_metadatastore(
        DataToken(token_address).get_metadata_url(),
        document_id
    )
