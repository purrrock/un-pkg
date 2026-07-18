import os
import struct

def unpack_pkg(pkg_path: str, out_dir: str):
    """
    Алгоритм прямого чтения C-структур архива .pkg (Little-Endian)
    """
    with open(pkg_path, 'rb') as f:
        # Чтение глобального заголовка (32 байта)
        header_data = f.read(32)
        magic, unknown, file_count, r1, r2 = struct.unpack('<2sHIII', header_data[:16])
        
        if magic != b'CR':
            raise ValueError(f"Invalid Magic Bytes: {magic}")
            
        print(f"[INFO] Archive valid. Files to extract: {file_count}")

        # Чтение таблицы файлов
        entries = []
        for _ in range(file_count):
            entry_data = f.read(16)
            name_hash, data_offset, data_size, name_length = struct.unpack('<IIII', entry_data)
            entries.append({
                'hash': name_hash,
                'offset': data_offset,
                'size': data_size,
                'name_len': name_length
            })

        # Чтение таблицы имен (String Table)
        # Строки идут непрерывно, без нуль-терминаторов
        for entry in entries:
            name_bytes = f.read(entry['name_len'])
            entry['path'] = name_bytes.decode('utf-8')

        # Извлечение полезной нагрузки по абсолютным смещениям
        for entry in entries:
            f.seek(entry['offset'])
            file_data = f.read(entry['size'])
            
            # Подготовка дерева директорий
            target_path = os.path.join(out_dir, entry['path'])
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            
            with open(target_path, 'wb') as out_f:
                out_f.write(file_data)
                
            print(f"Extracted: {entry['path']} (Size: {entry['size']} bytes, Offset: {hex(entry['offset'])})")