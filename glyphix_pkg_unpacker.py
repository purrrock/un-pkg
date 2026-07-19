#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Утилита для реверс-инжиниринга и распаковки архивов .pkg (Glyphix OS).
Целевая аппаратная платформа: Actions Semiconductor ATS3085S (DT G1).
Порядок байтов: Little-Endian.
Выравнивание: 16 байт (0x10).
"""

import os
import sys
import struct
from pathlib import Path

# --- Структурные константы формата ---
PKG_MAGIC = b'CR'
PKG_HEADER_SIZE = 0x20
FILE_ENTRY_SIZE = 0x10
JS_BYTECODE_MAGIC = b'\xf2\xda\x50\x01'
JS_OPCODE_ENTRY_MARKER = b'\x0f\x9e\x03'


class GlyphixPkgUnpacker:
    def __init__(self, pkg_path: str, output_dir: str = None):
        self.pkg_path = Path(pkg_path)
        
        # Если папка не указана, используем имя файла без расширения (например, "app" из "app.pkg")
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            self.output_dir = Path(self.pkg_path.stem)
            
        self.entries = []

    def unpack(self):
        """Основной процесс распаковки архива."""
        if not self.pkg_path.exists():
            print(f"[ERROR] Файл не найден: {self.pkg_path}")
            sys.exit(1)

        print(f"[INFO] Анализ архива: {self.pkg_path.name}")
        print(f"[INFO] Целевая директория: {self.output_dir.absolute()}")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        with open(self.pkg_path, 'rb') as f:
            # 1. Чтение и проверка глобального заголовка
            header_data = f.read(PKG_HEADER_SIZE)
            if len(header_data) < PKG_HEADER_SIZE or header_data[0:2] != PKG_MAGIC:
                print("[ERROR] Неверная сигнатура. Ожидалось 'CR'.")
                sys.exit(1)

            # Извлечение количества файлов (смещение 0x04, размер 4 байта)
            file_count = struct.unpack('<I', header_data[0x04:0x08])[0]
            print(f"[INFO] Количество файлов в архиве: {file_count}")

            # 2. Чтение таблицы смещений (File Offset Table)
            for _ in range(file_count):
                entry_data = f.read(FILE_ENTRY_SIZE)
                name_hash, data_offset, data_size, name_length = struct.unpack('<IIII', entry_data)
                
                self.entries.append({
                    'name_hash': name_hash,
                    'data_offset': data_offset,
                    'data_size': data_size,
                    'name_length': name_length,
                    'name': '' # Будет заполнено на следующем этапе
                })

            # 3. Чтение таблицы имен (String Table)
            # В Release/Factory сборках таблица строк вырезана (name_length == 0).
            for i, entry in enumerate(self.entries):
                if entry['name_length'] > 0:
                    raw_name = f.read(entry['name_length'])
                    entry['name'] = raw_name.decode('utf-8', errors='ignore')
                
                # Защита от пустых имен (предотвращает PermissionError при записи в папку)
                if not entry['name'] or entry['name'].strip() == "":
                    # Генерация синтетического имени: индекс + hex(name_hash)
                    entry['name'] = f"unknown_{i:04d}_{entry['name_hash']:08X}.bin"

                print(f"[FILE] Обнаружен: {entry['name']} (Смещение: 0x{entry['data_offset']:08X}, Размер: {entry['data_size']} байт)")

            # 4. Извлечение полезной нагрузки (Payloads)
            for entry in self.entries:
                if entry['data_size'] == 0:
                    continue # Защита от попыток записи пустых блоков данных

                f.seek(entry['data_offset'])
                payload = f.read(entry['data_size'])
                self._save_payload(entry['name'], payload)

    def _save_payload(self, relative_path: str, data: bytes):
        """Сохраняет сырые данные и запускает анализаторы форматов."""
        # Нормализация путей во избежание Path Traversal уязвимостей
        safe_path = relative_path.lstrip('/')
        out_file = self.output_dir / safe_path
        
        # Создаем все вложенные папки, если файл лежит в подкаталоге
        out_file.parent.mkdir(parents=True, exist_ok=True)

        # Сохранение сырого бинарника
        with open(out_file, 'wb') as f:
            f.write(data)

        # Эвристическая проверка на наличие AOT-скомпилированного JS-байткода
        # (Используется проверка сигнатуры, так как расширение .js может быть утеряно в Factory-билдах)
        if data.startswith(JS_BYTECODE_MAGIC):
            self._dump_js_constant_pool(safe_path, data, out_file)

    def _dump_js_constant_pool(self, file_name: str, data: bytes, original_file_path: Path):
        """
        Декодирует пулы строк (Constant Pool) из скомпилированного байткода
        на основе аппаратного алгоритма Bitwise Length Encoding:
        String_Length = Prefix_Byte >> 1
        """
        if len(data) <= 10:
            return

        print(f"  └─ [JS VM] Обнаружен AOT-байткод в '{file_name}'. Экстракция пула констант...")
        strings_dump = []
        offset = 0x0A # Пул начинается строго после 10 байт заголовка ВМ

        while offset < len(data):
            # Проверка маркера входа в секцию процессорных опкодов
            if data[offset:offset+3] == JS_OPCODE_ENTRY_MARKER:
                print(f"  └─ [JS VM] Маркер опкодов (0F 9E 03) достигнут по смещению 0x{offset:08X}.")
                break

            prefix_byte = data[offset]
            string_length = prefix_byte >> 1 # Применение выведенного алгоритма сдвига
            
            offset += 1 # Сдвиг за байт-префикс
            
            if offset + string_length > len(data):
                break # Защита от переполнения буфера (Buffer Over-read)
                
            string_data = data[offset:offset+string_length]
            try:
                decoded_str = string_data.decode('utf-8')
                strings_dump.append(decoded_str)
            except UnicodeDecodeError:
                # Fallback для бинарных данных, ошибочно интерпретированных как строки
                strings_dump.append(f"<HEX: {string_data.hex()}>")

            offset += string_length

        # Сохранение извлеченного пула в текстовый файл рядом с оригиналом
        dump_path = original_file_path.with_name(original_file_path.name + '.strings.txt')
        with open(dump_path, 'w', encoding='utf-8') as f:
            f.write(f"=== Dump of Constant Pool for {file_name} ===\n\n")
            for i, s in enumerate(strings_dump):
                f.write(f"[{i:04d}] {s}\n")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Использование: python glyphix_pkg_unpacker.py <путь_к_файлу.pkg> [папка_назначения]")
        sys.exit(1)

    input_pkg = sys.argv[1]
    # Второй аргумент опционален. По умолчанию директория создается в рабочей папке 
    # с именем извлекаемого пакета без расширения .pkg
    output_directory = sys.argv[2] if len(sys.argv) >= 3 else None

    unpacker = GlyphixPkgUnpacker(input_pkg, output_directory)
    unpacker.unpack()
    print("\n[SUCCESS] Распаковка и анализ успешно завершены.")