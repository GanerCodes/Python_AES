from tables import *

def AES_KeyExpansionCore(inp, i):
    # Step 1
    t = inp[0]
    inp[0] = inp[1]
    inp[1] = inp[2]
    inp[2] = inp[3]
    inp[3] = t
    
    # Step 2
    inp[0] = AES_S_Box[inp[0]]
    inp[1] = AES_S_Box[inp[1]]
    inp[2] = AES_S_Box[inp[2]]
    inp[3] = AES_S_Box[inp[3]]
    
    # Step 3
    inp[0] = inp[0] ^ AES_Rcon[i]

def AES_KeyExpansion(inputKey, expandedKeys):
    for i in range(16):
        expandedKeys[i] = inputKey[i]
    
    bytesGenerated = 16
    rconIteration = 1
    buffer = bytearray(4)
    
    while bytesGenerated < 176:
        for i in range(4):
            buffer[i] = expandedKeys[i + bytesGenerated - 4]
        
        if bytesGenerated % 16 == 0:
            AES_KeyExpansionCore(buffer, rconIteration)
            rconIteration += 1
        
        for a in range(4):
            expandedKeys[bytesGenerated] = expandedKeys[bytesGenerated - 16] ^ buffer[a]
            bytesGenerated += 1

def AES_AddRoundKey(state, roundKey):
    for i in range(len(state)):
        state[i] = state[i] ^ roundKey[i]

def zeroPad(message):
    msgLength = len(message)
    if msgLength % 16 != 0:
        newMsgLength = 16 * (msgLength // 16 + 1)
        newMessage = bytearray(newMsgLength)
        for i in range(newMsgLength):
            if i < msgLength:
                newMessage[i] = message[i]
        return newMessage
    return message