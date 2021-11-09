from tables import *
from aes import *

def AES_SubBytes(state):
    for i, v in enumerate(state):
        state[i] = AES_S_Box[state[i]]

def AES_ShiftRows(state):
    buffer = bytearray(16)
    for i, v in enumerate([0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11]):
        buffer[i] = state[v]
        
    for i in range(len(state)): state[i] = buffer[i]

def AES_MixColumns(state):
    buffer = bytearray(16)
    
    buffer[0] = AES_Mul2[state[0]] ^ AES_Mul3[state[1]] ^ state[2] ^ state[3]
    buffer[1] = state[0] ^ AES_Mul2[state[1]] ^ AES_Mul3[state[2]] ^ state[3]
    buffer[2] = state[0] ^ state[1] ^ AES_Mul2[state[2]] ^ AES_Mul3[state[3]]
    buffer[3] = AES_Mul3[state[0]] ^ state[1] ^ state[2] ^ AES_Mul2[state[3]]

    buffer[4] = AES_Mul2[state[4]] ^ AES_Mul3[state[5]] ^ state[6] ^ state[7]
    buffer[5] = state[4] ^ AES_Mul2[state[5]] ^ AES_Mul3[state[6]] ^ state[7]
    buffer[6] = state[4] ^ state[5] ^ AES_Mul2[state[6]] ^ AES_Mul3[state[7]]
    buffer[7] = AES_Mul3[state[4]] ^ state[5] ^ state[6] ^ AES_Mul2[state[7]]
    
    buffer[8] = AES_Mul2[state[8]] ^ AES_Mul3[state[9]] ^ state[10] ^ state[11]
    buffer[9] = state[8] ^ AES_Mul2[state[9]] ^ AES_Mul3[state[10]] ^ state[11]
    buffer[10] = state[8] ^ state[9] ^ AES_Mul2[state[10]] ^ AES_Mul3[state[11]]
    buffer[11] = AES_Mul3[state[8]] ^ state[9] ^ state[10] ^ AES_Mul2[state[11]]
    
    buffer[12] = AES_Mul2[state[12]] ^ AES_Mul3[state[13]] ^ state[14] ^ state[15]
    buffer[13] = state[12] ^ AES_Mul2[state[13]] ^ AES_Mul3[state[14]] ^ state[15]
    buffer[14] = state[12] ^ state[13] ^ AES_Mul2[state[14]] ^ AES_Mul3[state[15]]
    buffer[15] = AES_Mul3[state[12]] ^ state[13] ^ state[14] ^ AES_Mul2[state[15]]
    
    for i in range(len(state)): state[i] = buffer[i]


def AES_Encrypt_Block(message, expandedKey, roundNumber):
    state = bytearray(len(message))
    for i in range(len(message)):
        state[i] = message[i]
    
    AES_AddRoundKey(state, expandedKey)
    
    for i in range(roundNumber - 1):
        AES_SubBytes(state)
        AES_ShiftRows(state)
        AES_MixColumns(state)
        AES_AddRoundKey(state, expandedKey[16 * (i + 1):])
    
    AES_SubBytes(state)
    AES_ShiftRows(state)
    AES_AddRoundKey(state, expandedKey[160:])
    
    return state

def AES_Encrypt(message, key, expandedKey = None, roundNumber = 10):
    if not expandedKey:
        expandedKey = bytearray(176)
        AES_KeyExpansion(key, expandedKey)
    
    message = zeroPad(message)
    
    result = bytearray()
    for i in range(0, len(message), 16):
        result += AES_Encrypt_Block(message[i:i + 16], expandedKey, roundNumber)
    return result