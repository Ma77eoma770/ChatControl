import asyncio
import os
import math
import hashlib
import traceback
from telethon import TelegramClient, utils
from telethon.tl.types import DocumentAttributeFilename
from telethon.tl.functions.upload import SaveBigFilePartRequest, SaveFilePartRequest
from telethon.tl.functions.messages import SendMediaRequest
from telethon.tl.types import InputMediaUploadedDocument, InputDocumentFileLocation

CHUNK_SIZE = 512 * 1024  # 512 KB per chunk to be safe and fast

async def upload_file(client: TelegramClient, file_path: str, progress_callback=None) -> tuple:
    """
    Carica un file su Telegram parallelizzando l'upload per massimizzare la velocità.
    Ritorna InputFileBig / InputFile
    """
    import random
    file_id = random.randint(-2**63, 2**63 - 1)
    file_size = os.path.getsize(file_path)
    total_parts = math.ceil(file_size / CHUNK_SIZE)
    is_large = file_size > 10 * 1024 * 1024

    uploaded_bytes = 0
    upload_lock = asyncio.Lock()

    async def _upload_part(part_index: int):
        nonlocal uploaded_bytes
        with open(file_path, 'rb') as f:
            f.seek(part_index * CHUNK_SIZE)
            chunk = f.read(CHUNK_SIZE)
            
        if is_large:
            req = SaveBigFilePartRequest(file_id, part_index, total_parts, chunk)
        else:
            req = SaveFilePartRequest(file_id, part_index, chunk)
            
        await client(req)
        async with upload_lock:
            uploaded_bytes += len(chunk)
            if progress_callback:
                await progress_callback(uploaded_bytes, file_size)

    # Use a semaphore to limit concurrency and avoid FloodWaits
    semaphore = asyncio.Semaphore(5)

    async def _worker(part_index: int):
        async with semaphore:
            await _upload_part(part_index)

    tasks = [_worker(i) for i in range(total_parts)]
    await asyncio.gather(*tasks)

    filename = os.path.basename(file_path)
    file_hash = ''
    if not is_large:
        md5 = hashlib.md5()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                md5.update(chunk)
        file_hash = md5.hexdigest()

    if is_large:
        from telethon.tl.types import InputFileBig
        return InputFileBig(file_id, total_parts, filename)
    else:
        from telethon.tl.types import InputFile
        return InputFile(file_id, total_parts, filename, file_hash)

async def download_file(client: TelegramClient, location, out_file: str, file_size: int, progress_callback=None):
    """
    Scarica un file da Telegram parallelizzando la ricezione in blocchi.
    `location` deve essere un tipo Telethon (Document, Photo) o un InputFileLocation.
    """
    from telethon import utils as tl_utils
    from telethon.tl.functions.upload import GetFileRequest
    
    # Converti in InputFileLocation se necessario
    try:
        input_location = tl_utils.get_input_location(location)
    except Exception:
        input_location = location

    total_parts = math.ceil(file_size / CHUNK_SIZE) if file_size > 0 else 0
    downloaded_bytes = 0
    lock = asyncio.Lock()

    # Pre-alloca il file
    with open(out_file, 'wb') as f:
        if file_size > 0:
            f.seek(file_size - 1)
            f.write(b'\0')

    semaphore = asyncio.Semaphore(5)

    async def _download_part(part_index: int):
        nonlocal downloaded_bytes
        offset = part_index * CHUNK_SIZE
        async with semaphore:
            result = await client(GetFileRequest(
                location=input_location,
                offset=offset,
                limit=CHUNK_SIZE
            ))
            
            async with lock:
                with open(out_file, 'r+b') as f:
                    f.seek(offset)
                    f.write(result.bytes)
                downloaded_bytes += len(result.bytes)
                if progress_callback:
                    await progress_callback(downloaded_bytes, file_size)

    tasks = [_download_part(i) for i in range(total_parts)]
    await asyncio.gather(*tasks)
    return out_file
