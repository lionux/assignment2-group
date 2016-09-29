import Network
import argparse
from time import sleep
import hashlib
import time

class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    ## length of md5 checksum in hex
    checksum_length = 32 
        
    def __init__(self, seq_num, msg_S):
        self.seq_num = seq_num
        self.msg_S = msg_S

    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        #extract the fields
        seq_num = int(byte_S[Packet.length_S_length : Packet.length_S_length+Packet.seq_num_S_length])
        msg_S = byte_S[Packet.length_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        return self(seq_num, msg_S)
        
        
    def get_byte_S(self):
        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(self.length_S_length)
        #compute the checksum
        checksum = hashlib.md5((length_S+seq_num_S+self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return length_S + seq_num_S + checksum_S + self.msg_S
   
    
    @staticmethod
    def corrupt(byte_S):
    
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length : Packet.seq_num_S_length+Packet.seq_num_S_length]
        checksum_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length : Packet.seq_num_S_length+Packet.length_S_length+Packet.checksum_length]
        msg_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        
    
        checksum = hashlib.md5(str(length_S+seq_num_S+msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()

        return checksum_S != computed_checksum_S
        
    @staticmethod
    def get_seq_num(byte_S):
        return int(byte_S[Packet.length_S_length : Packet.length_S_length+Packet.seq_num_S_length])
    
    @staticmethod
    def get_msg(byte_S):
        return byte_S[Packet.length_S_length+Packet.seq_num_S_length+Packet.checksum_length :]

class RDT:
    ## latest sequence number used in a packet
    seq_num = 1
    ## buffer of bytes read from network
    byte_buffer = '' 

    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)
    
    def disconnect(self):
        self.network.disconnect()
        
    def rdt_1_0_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        self.seq_num += 1
        self.network.udt_send(p.get_byte_S())
        
    def rdt_1_0_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        while True:
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.length_S_length):
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S #not enough bytes to read the whole packet
            #create packet from buffer content and add to return string
            p = Packet.from_byte_S(self.byte_buffer[0:length])
            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
            #remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            #if this was the last packet, will return on the next iteration
            
    
    def rdt_2_1_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        self.network.udt_send(p.get_byte_S())
        #Get the ACK back and store in ret_S
        ret_S = None
        while True:
            ret_S = None
            byte_S = None
            while ret_S is None:
                byte_S = self.network.udt_receive()
                self.byte_buffer += byte_S
                while True:
                    try:
                        if(len(self.byte_buffer) < Packet.length_S_length):
                            break
                        length = int(self.byte_buffer[:Packet.length_S_length])
                        if len(self.byte_buffer) < length:
                            break
                        p = Packet.from_byte_S(self.byte_buffer[0:length]) 
                        ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                        self.byte_buffer = self.byte_buffer[length:]
                    except Exception as e:
                        ret_S = "CORRUPT"
                        break
            #print("got ret_S in send method: "+ret_S+"."+str(ret_S == "ACK"))
            if ret_S == "CORRUPT" or ret_S == "NAK":
                print ("Receiver got corrupt packet, resending from SEND "+msg_S)
                p = Packet(self.seq_num, msg_S)
                self.network.udt_send(p.get_byte_S())
                time.sleep(1)
            elif ret_S == "ACK":
                print ("Receiver got a good packet, received ACK on SEND")
                self.seq_num += 1
                #print("receieved ack on send, breaking")
                break
            #we need to ask them to retransmit (we got the next message)
            else:
                print("We got a packet out of order, ask for a resend")
                p = Packet(self.seq_num, "NAK")
                self.network.udt_send(p.get_byte_S())
                break

        print("ENDING SEND FUNC\n\n")
        time.sleep(1)


    def rdt_2_1_receive(self):
        ret_S = None
        byte_S = None
        while ret_S is None:
            byte_S = self.network.udt_receive()
            #print("BYTE_S: "+byte_S)
            self.byte_buffer += byte_S
            while True:
                try:
                    if(len(self.byte_buffer) < Packet.length_S_length):
                        break
                    length = int(self.byte_buffer[:Packet.length_S_length])
                    if len(self.byte_buffer) < length:
                        break
                    p = Packet.from_byte_S(self.byte_buffer[0:length])
                    ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                    self.byte_buffer = self.byte_buffer[length:]
                except Exception as e:
                    ret_S = "CORRUPT"
                    break
    
        if ret_S != "CORRUPT":
            print ("Got good packet in RECV, send ACK")
            p = Packet(self.seq_num, "ACK")
            self.network.udt_send(p.get_byte_S())
            time.sleep(1)
            return ret_S
        elif ret_S == "ACK":
            return None
        else:
            #print(str(self.seq_num)+" msg: "+"NAK")
            print("Packet from sender is corrupt, sending NAK")
            p = Packet(self.seq_num, "NAK")
            self.network.udt_send(p.get_byte_S())
            time.sleep(1)
            return None

    def rdt_3_0_send(self, msg_S):
        pass
        
    def rdt_3_0_receive(self):
        pass
        

if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()
    
    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_1_0_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_1_0_receive())
        rdt.disconnect()
        
        
    else:
        sleep(1)
        print(rdt.rdt_1_0_receive())
        rdt.rdt_1_0_send('MSG_FROM_SERVER')
        rdt.disconnect()
        


        
        
