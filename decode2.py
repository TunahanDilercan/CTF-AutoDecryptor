import base64, binascii, codecs
from string import printable

def is_probably_readable(text, threshold=0.95):
    if not text:
        return False
    printable_chars = sum(c in printable for c in text)
    return (printable_chars / len(text)) >= threshold

# Tanımlama kriterleri için yardımcı fonksiyonlar
def matches_base64(text):
    try:
        # Base64 karakter seti ve padding kontrolü
        if all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in text) and len(text) % 4 == 0:
            base64.b64decode(text)
            return True
    except Exception:
        pass
    return False

def matches_hex(text):
    try:
        bytes.fromhex(text)
        return True
    except Exception:
        return False

def matches_rot13(text):
    # ROT13 sadece harfler içeriyor ve başka yöntem belirtisi yoktur.
    # Bu nedenle, belirli bir eşleşme kriteri yerine potansiyel olarak her şey olabilir.
    return any(c.isalpha() for c in text)

# Diğer dönüşüm fonksiyonları
def try_base64(ciphertext):
    try:
        decoded = base64.b64decode(ciphertext)
        decoded_text = decoded.decode('utf-8', errors='replace')
        if is_probably_readable(decoded_text):
            return decoded_text
    except Exception:
        pass
    return None

def try_hex(ciphertext):
    try:
        decoded = bytes.fromhex(ciphertext)
        decoded_text = decoded.decode('utf-8', errors='replace')
        if is_probably_readable(decoded_text):
            return decoded_text
    except Exception:
        pass
    return None

def try_rot13(ciphertext):
    try:
        decoded = codecs.decode(ciphertext, 'rot_13')
        if is_probably_readable(decoded):
            return decoded
    except Exception:
        pass
    return None

def caesar_decode(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            if char.isupper():
                result += chr((ord(char) - shift - 65) % 26 + 65)
            else:
                result += chr((ord(char) - shift - 97) % 26 + 97)
        else:
            result += char
    return result

def try_caesar(ciphertext):
    results = []
    for shift in range(1, 26):
        decoded = caesar_decode(ciphertext, shift)
        if is_probably_readable(decoded):
            results.append((shift, decoded))
    return results if results else None

def single_byte_xor(input_bytes, key):
    return bytes([b ^ key for b in input_bytes])

def try_single_byte_xor(ciphertext):
    try:
        cipher_bytes = bytes.fromhex(ciphertext)
    except Exception:
        cipher_bytes = ciphertext.encode()

    probable_results = []
    for key in range(256):
        result_bytes = single_byte_xor(cipher_bytes, key)
        try:
            result_text = result_bytes.decode('utf-8', errors='replace')
        except Exception:
            continue
        if is_probably_readable(result_text):
            probable_results.append((key, result_text))
    return probable_results if probable_results else None

# Tanımlama aşaması: Olası yöntemleri belirleme
def identify_possible_methods(ciphertext):
    possible_methods = []
    if matches_base64(ciphertext):
        possible_methods.append("Base64")
    if matches_hex(ciphertext):
        possible_methods.append("Hex")
    # ROT13 ve Sezar için harf içeriği kontrolü yapıyoruz
    if matches_rot13(ciphertext):
        possible_methods.append("ROT13/Sezar/XOR")
    # Burada ROT13/Sezar/XOR gibi bir grup önerdik çünkü harf içeren metin
    # bunlardan herhangi biri olabilir. Diğer yöntemler için daha detaylı
    # kontroller eklenebilir.
    return possible_methods

# Kullanıcının seçimlerine göre yöntemi uygulama
def apply_method(method, ciphertext):
    if method == "Base64":
        result = try_base64(ciphertext)
        print(f"Base64 Sonuç: {result}" if result else "Base64 ile çözüm bulunamadı.")
    elif method == "Hex":
        result = try_hex(ciphertext)
        print(f"Hex Sonuç: {result}" if result else "Hex ile çözüm bulunamadı.")
    elif method == "ROT13":
        result = try_rot13(ciphertext)
        print(f"ROT13 Sonuç: {result}" if result else "ROT13 ile çözüm bulunamadı.")
    elif method == "Caesar":
        results = try_caesar(ciphertext)
        if results:
            for shift, text in results:
                print(f"Shift {shift}: {text}")
        else:
            print("Sezar ile çözüm bulunamadı.")
    elif method == "SingleByteXOR":
        results = try_single_byte_xor(ciphertext)
        if results:
            for key, text in results:
                print(f"Key {key}: {text}")
        else:
            print("Single Byte XOR ile çözüm bulunamadı.")
    else:
        print(f"{method} için desteklenmeyen bir yöntem.")

if __name__ == "__main__":
    ciphertext = input("Şifreli metni girin: ").strip()

    # 1. Tanımlama aşaması: Olası yöntemleri belirle
    possible_methods = identify_possible_methods(ciphertext)
    print("\nOlası yöntemler tespit edildi:", possible_methods if possible_methods else "Bilinmiyor")

    # 2. Kullanıcıdan seçim al
    print("\nDenenecek yöntem seçenekleri:")
    for idx, method in enumerate(possible_methods, start=1):
        print(f"{idx}. {method}")
    print(f"{len(possible_methods)+1}. Hepsini dene")

    choice = input("Hangi yöntemi denemek istersiniz? (numara giriniz): ").strip()

    try:
        choice = int(choice)
    except ValueError:
        print("Geçersiz seçim.")
        exit(1)

    # 3. Seçime göre yöntemi uygula
    if choice == len(possible_methods) + 1:
        # Hepsini dene
        for method in possible_methods:
            print(f"\n[{method} deneniyor]")
            apply_method(method, ciphertext)
    elif 1 <= choice <= len(possible_methods):
        selected_method = possible_methods[choice - 1]
        print(f"\n[{selected_method} deneniyor]")
        apply_method(selected_method, ciphertext)
    else:
        print("Geçersiz seçim.")
