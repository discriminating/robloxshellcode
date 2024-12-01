import sys

def string_to_hex_chunks(input_string):
    padded_string = input_string + '\0' * ((8 - len(input_string) % 8) % 8)
    
    chunks = []
    for i in range(0, len(padded_string), 8):
        chunk = padded_string[i:i+8]
        # little-endian
        hex_value = ''.join(f'{ord(char):02x}' for char in reversed(chunk))
        chunks.append(f'0x{hex_value}')
    
    return chunks

def generate_code(string):
    hex_chunks = string_to_hex_chunks(string)
    code = []
    for i, chunk in enumerate(hex_chunks):
        code.append(f"x.text{i} = {chunk};")
    return '\n'.join(code)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python stringify.py <string>")
        sys.exit(1)
    
    input_string = sys.argv[1]
    code_representation = generate_code(input_string)
    print(code_representation)
