import zlib
import os


def extract_file_based_on_header_info(
    apk_file, local_header_info, central_directory_info
):
    """
    Extracts a single file from the apk_file based on the information provided from the offset and the header_info.
    It takes into account that the compression method provided might not be STORED or DEFLATED! The returned
    'indicator', shows what compression method was used. Besides the standard STORED/DEFLATE it may return
    'DEFLATED_TAMPERED', which means that the compression method found was not DEFLATED(8) but it should have been,
    and 'STORED_TAMPERED' which means that the compression method found was not STORED(0) but should have been.

    :param apk_file: The APK file e.g. with open('test.apk', 'rb') as apk_file
    :type apk_file: bytesIO
    :param local_header_info: The local header dictionary info for that specific filename
    :type local_header_info: dict
    :param central_directory_info: The central directory entry for that specific filename
    :type central_directory_info: dict
    :return: Returns the actual extracted data for that file along with an indication of whether a static analysis evasion technique was used or not.
    :rtype: set(bytes, str)
    """
    if not local_header_info or not central_directory_info:
        return None, None
    
    filename_length = local_header_info["file_name_length"]
    if (
        local_header_info["compressed_size"] == 0
        or local_header_info["uncompressed_size"] == 0
    ):
        compressed_size = central_directory_info["compressed_size"]
        uncompressed_size = central_directory_info["uncompressed_size"]
    else:
        compressed_size = local_header_info["compressed_size"]
        uncompressed_size = local_header_info["uncompressed_size"]

    extra_field_length = local_header_info["extra_field_length"]
    compression_method = local_header_info["compression_method"]
    # Skip the offset + local header to reach the compressed data
    local_header_size = 30  # Size of the local header in bytes
    offset = central_directory_info["relative_offset_of_local_file_header"]
    apk_file.seek(
        offset + local_header_size + filename_length + extra_field_length
    )
    if compression_method == 0:  # Stored (no compression)
        uncompressed_data = apk_file.read(uncompressed_size)
        extracted_data = uncompressed_data
        indicator = 'STORED'
    elif compression_method == 8:
        compressed_data = apk_file.read(compressed_size)
        # -15 for windows size due to raw stream with no header or trailer
        extracted_data = zlib.decompress(compressed_data, -15)
        indicator = 'DEFLATED'
    elif compressed_size == uncompressed_size:
        compressed_data = apk_file.read(uncompressed_size)
        extracted_data = compressed_data
        indicator = 'STORED_TAMPERED'
    else:
        cur_loc = apk_file.tell()
        try:
            compressed_data = apk_file.read(compressed_size)
            extracted_data = zlib.decompress(compressed_data, -15)
            indicator = 'DEFLATED_TAMPERED'
        except:
            apk_file.seek(cur_loc)
            compressed_data = apk_file.read(uncompressed_size)
            extracted_data = compressed_data
            indicator = 'STORED_TAMPERED'
    return extracted_data, indicator
