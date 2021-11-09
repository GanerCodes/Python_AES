from tables import *
from aes import *

def AES_SubBytes_Inverse(state):
    for i, v in enumerate(state):
        state[i] = AES_S_Box_Inverse[state[i]]

def AES_ShiftRows_Inverse(state):
    buffer = bytearray(16)
    for i, v in enumerate([0,13,10,7,4,1,14,11,8,5,2,15,12,9,6,3]):
        buffer[i] = state[v]
    
    for i in range(len(state)): state[i] = buffer[i]

def AES_MixColumns_Inverse(state):
    buffer = bytearray(16)
    
    buffer[0] = AES_Mul14[state[0]] ^ AES_Mul11[state[1]] ^ AES_Mul13[state[2]] ^ AES_Mul9[state[3]]
    buffer[1] = AES_Mul9[state[0]] ^ AES_Mul14[state[1]] ^ AES_Mul11[state[2]] ^ AES_Mul13[state[3]]
    buffer[2] = AES_Mul13[state[0]] ^ AES_Mul9[state[1]] ^ AES_Mul14[state[2]] ^ AES_Mul11[state[3]]
    buffer[3] = AES_Mul11[state[0]] ^ AES_Mul13[state[1]] ^ AES_Mul9[state[2]] ^ AES_Mul14[state[3]]

    buffer[4] = AES_Mul14[state[4]] ^ AES_Mul11[state[5]] ^ AES_Mul13[state[6]] ^ AES_Mul9[state[7]]
    buffer[5] = AES_Mul9[state[4]] ^ AES_Mul14[state[5]] ^ AES_Mul11[state[6]] ^ AES_Mul13[state[7]]
    buffer[6] = AES_Mul13[state[4]] ^ AES_Mul9[state[5]] ^ AES_Mul14[state[6]] ^ AES_Mul11[state[7]]
    buffer[7] = AES_Mul11[state[4]] ^ AES_Mul13[state[5]] ^ AES_Mul9[state[6]] ^ AES_Mul14[state[7]]

    buffer[8] = AES_Mul14[state[8]] ^ AES_Mul11[state[9]] ^ AES_Mul13[state[10]] ^ AES_Mul9[state[11]]
    buffer[9] = AES_Mul9[state[8]] ^ AES_Mul14[state[9]] ^ AES_Mul11[state[10]] ^ AES_Mul13[state[11]]
    buffer[10] = AES_Mul13[state[8]] ^ AES_Mul9[state[9]] ^ AES_Mul14[state[10]] ^ AES_Mul11[state[11]]
    buffer[11] = AES_Mul11[state[8]] ^ AES_Mul13[state[9]] ^ AES_Mul9[state[10]] ^ AES_Mul14[state[11]]

    buffer[12] = AES_Mul14[state[12]] ^ AES_Mul11[state[13]] ^ AES_Mul13[state[14]] ^ AES_Mul9[state[15]]
    buffer[13] = AES_Mul9[state[12]] ^ AES_Mul14[state[13]] ^ AES_Mul11[state[14]] ^ AES_Mul13[state[15]]
    buffer[14] = AES_Mul13[state[12]] ^ AES_Mul9[state[13]] ^ AES_Mul14[state[14]] ^ AES_Mul11[state[15]]
    buffer[15] = AES_Mul11[state[12]] ^ AES_Mul13[state[13]] ^ AES_Mul9[state[14]] ^ AES_Mul14[state[15]]
    
    for i in range(len(state)): state[i] = buffer[i]

def AES_Decrypt_Block(message, key, expandedKey, roundNumber):
    state = bytearray(len(message))
    for i in range(len(message)):
        state[i] = message[i]
    
    AES_AddRoundKey(state, expandedKey[160:])
    
    for i in range(roundNumber - 1, 0, -1):
        AES_ShiftRows_Inverse(state)
        AES_SubBytes_Inverse(state)
        AES_AddRoundKey(state, expandedKey[16 * i:])
        AES_MixColumns_Inverse(state)
    
    AES_ShiftRows_Inverse(state)
    AES_SubBytes_Inverse(state)
    AES_AddRoundKey(state, expandedKey)
    
    return state

def AES_Decrypt(message, key, expandedKey = None, roundNumber = 10):
    if not expandedKey:
        expandedKey = bytearray(176)
        AES_KeyExpansion(key, expandedKey)
    
    message = zeroPad(message)
    
    result = bytearray()
    for i in range(0, len(message), 16):
        result += AES_Decrypt_Block(message[i:i + 16], key, expandedKey, roundNumber)
    return result
