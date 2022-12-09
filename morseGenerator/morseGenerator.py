import re
from typing import List

MORSE_DICT = {'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 'G': '--.', 'H': '....',
              'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---', 'P': '.--.',
              'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
              'Y': '-.--', 'Z': '--..',
              '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
              '8': '---..',
              '9': '----.', '0': '-----',
              ',': '--..--',
              '.': '.-.-.-',
              '?': '..--..',
              '/': '-..-.',
              '-': '-....-',
              '(': '-.--.',
              ')': '-.--.-'
              }


def character_to_morse(character, default: bool, sign: List[str]):
    cipher_chr = ''
    if chr != ' ':
        cipher_chr += MORSE_DICT[character] + ' '
    else:
        cipher_chr = ' '
    if not default:
        # replace customized sign #method 1
        if len(sign) == 1:
            rep = {'.': sign[0]}
        else:
            rep = {'.': sign[0], '-': sign[1]}
        rep = dict((re.escape(k), v) for k, v in rep.items())
        pattern = re.compile('|'.join(rep.keys()))
        cipher_chr = pattern.sub(lambda m: rep[re.escape(m.group(0))], cipher_chr)
        # replace customized sign #method 2
        # cipher_chr.replace('.', sign[0]).replace('-', sign[1])
    return cipher_chr


def encrypt(text, sign:List[str] = []):
    cipher_text = ''
    is_default = True
    if len(sign) != 0:
        is_default = False
    elif len(sign) != 2:
        print('Only 2 sign will be deployed.')
    for letter in text:
        cipher_text += character_to_morse(letter, is_default, sign)
    return cipher_text


def decrypt(message):
    # extra space added at the end to access the
    # last morse code
    message += ' '

    decipher = ''
    citext = ''
    for letter in message:

        # checks for space
        if (letter != ' '):

            # counter to keep track of space
            i = 0

            # storing morse code of a single character
            citext += letter

        # in case of space
        else:
            # if i = 1 that indicates a new character
            i += 1

            # if i = 2 that indicates a new word
            if i == 2:

                # adding space to separate words
                decipher += ' '
            else:

                # accessing the keys using their values (reverse of encryption)
                decipher += list(MORSE_DICT.keys())[list(MORSE_DICT
                                                              .values()).index(citext)]
                citext = ''

    return decipher

def main():
    text = ''
    sign = []

    print('Input')
    text = input()
    print(f'\n{text}\n')
    print('Customize sign(2 input, split by space):')
    sign_str = input()
    if len(sign_str) > 0:
        if len(sign_str.split(' ')) > 0:
            sign = sign_str.split(' ')
        else:
            sign = sign_str.split('space')
    print(f'\n{sign[:2]}\n')
    print(f'Cipher\n{encrypt(text.upper(), sign)}\n')

if __name__ == '__main__':
    main()