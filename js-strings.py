def dump_js_bytecode_strings(js_filepath: str):
    """
    Экстрактор пула констант из AOT-скомпилированного JS (Glyphix OS).
    Анализирует Bitwise Length Encoding и останавливается на Entry Point Marker.
    """
    with open(js_filepath, 'rb') as f:
        # 1. Проверка сигнатуры VM
        magic = f.read(4)
        if magic != b'\xf2\xda\x50\x01':
            print("[WARN] Not a compiled JS file or plain text JS.")
            return

        # Пропуск 6 байт неизвестных метаданных
        f.seek(10)
        
        print(f"[INFO] Parsing Compiled JS String Pool: {js_filepath}")
        print("-" * 50)
        
        strings = []
        while True:
            # Читаем потенциальный байт длины или начало Entry Point Marker
            peek_marker = f.read(3)
            if not peek_marker:
                break # EOF
                
            # Сигнатура начала блока инструкций ВМ (End of String Pool)
            if peek_marker == b'\x0f\x9e\x03':
                print("[INFO] Reached Opcode Entry Point Marker (0F 9E 03). Stopping.")
                break
            
            # Возвращаем указатель на 2 байта назад, так как это был байт префикса, 
            # а не 3-байтовый маркер
            f.seek(-3, 1) 
            
            prefix_byte = f.read(1)
            if not prefix_byte:
                break
                
            # Вычисление аппаратной длины строки
            prefix_val = prefix_byte[0]
            str_length = prefix_val >> 1
            
            if str_length == 0:
                continue # Защита от нулевых длин (встречаются при выравнивании)
                
            # Чтение строки из пула
            string_data = f.read(str_length)
            
            try:
                decoded_str = string_data.decode('utf-8', errors='ignore')
                strings.append(decoded_str)
                current_offset = f.tell() - str_length - 1
                print(f"Offset 0x{current_offset:04X} | Len: {str_length:02d} | '{decoded_str}'")
            except Exception as e:
                print(f"[ERR] Failed to decode string at {f.tell()}: {e}")
                
        print("-" * 50)
        print(f"Total Strings Extracted: {len(strings)}")