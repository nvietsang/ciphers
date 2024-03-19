SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

RCON = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)

xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

class AES128:
    def __init__(self, key: bytes):
        self.Nr = 10
        self.Nk = 4
        self.round_keys = self.key_schedule(list(key))
        
    def key_schedule(self, key) -> list:
        # Round 0
        round_keys = key[:]
        
        # Round ri: 1-10
        for ri in range(1, self.Nr+1):
            fi = (ri-1) * 16    # fi: index of  1-st element of old round key
            li = fi + 12        # li: index of 12-th element of old round key (3-rd column)

            # RotWord
            c0 = round_keys[li + 1]
            c1 = round_keys[li + 2]
            c2 = round_keys[li + 3]
            c3 = round_keys[li    ]

            # SubWord
            c0 = SBOX[c0]
            c1 = SBOX[c1]
            c2 = SBOX[c2]
            c3 = SBOX[c3]

            # XOR
            c0 ^= round_keys[fi + 0]
            c1 ^= round_keys[fi + 1]
            c2 ^= round_keys[fi + 2]
            c3 ^= round_keys[fi + 3]

            # Rcon
            c0 ^= RCON[ri]

            # New round key
            ni = li + 4         # ni: index of  1-st element of new round key
            round_keys.append(c0)
            round_keys.append(c1)
            round_keys.append(c2)
            round_keys.append(c3)

            for _ in range(3):
                ni = ni + 4
                round_keys.append(round_keys[ni-16] ^ round_keys[ni-4])
                round_keys.append(round_keys[ni-15] ^ round_keys[ni-3])
                round_keys.append(round_keys[ni-14] ^ round_keys[ni-2])
                round_keys.append(round_keys[ni-13] ^ round_keys[ni-1])
        
        return round_keys

    def encrypt(self, plaintext: bytes) -> bytes:
        assert len(plaintext) == 16
        state = plaintext

        state = self._add_round_key(state, self.round_keys[:16])

        for rn in range(1,10):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, self.round_keys[rn*16 : (rn+1)*16])
        
        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, self.round_keys[160:])
        
        return state
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        assert len(ciphertext) == 16
        # TODO

    def _add_round_key(self, state: list, round_key: list) -> list:
        new_state = [v ^ k for (v, k) in zip(state, round_key)]
        return new_state

    def _sub_bytes(self, state: list) -> list:
        new_state = [SBOX[v] for v in state]
        return new_state
    
    def _shift_rows(self, state: list) -> list:
        new_state = state[:]
        # Row 2
        new_state[ 1] = state[ 5]
        new_state[ 5] = state[ 9]
        new_state[ 9] = state[13]
        new_state[13] = state[ 1]
        # Row 3
        new_state[ 2] = state[10]
        new_state[ 6] = state[14]
        new_state[10] = state[ 2]
        new_state[14] = state[ 6]
        # Row 3
        new_state[ 3] = state[15]
        new_state[ 7] = state[ 3]
        new_state[11] = state[ 7]
        new_state[15] = state[11]
        
        return new_state
    
    def _mix_columns(self, state: list) -> list:
        new_state = self._mix_single_column(state[  : 4])\
                  + self._mix_single_column(state[ 4: 8])\
                  + self._mix_single_column(state[ 8:12])\
                  + self._mix_single_column(state[12:  ])
        return new_state

    def _mix_single_column(self, column: list) -> list:
        t = column[0] ^ column[1] ^ column[2] ^ column[3]
        u = column[0]
        column[0] ^= t ^ xtime(column[0] ^ column[1])
        column[1] ^= t ^ xtime(column[1] ^ column[2])
        column[2] ^= t ^ xtime(column[2] ^ column[3])
        column[3] ^= t ^ xtime(column[3] ^ u)
        return column
    
def test_aes128():
    '''
    Test vectors are taken from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
    '''
    
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    m = bytes.fromhex("3243f6a8885a308d313198a2e0370734")

    cipher = AES128(key)

    # Key Schedule
    bytes(cipher.round_keys[-16:]) == bytes.fromhex("d014f9a8c9ee2589e13f0cc8b6630ca6")

    # Encryption
    c0 = cipher.encrypt(m)
    assert bytes(c0) == bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
    print("OK")

if __name__ == "__main__":
    test_aes128()