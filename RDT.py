import Network
import argparse
from time import sleep
import hashlib


class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    packet_type_length = 1
    ## length of md5 checksum in hex
    checksum_length = 32 
        
    def __init__(self, packet_type, seq_num, msg_S):
        self.packet_type = packet_type
        self.seq_num = seq_num
        self.msg_S = msg_S
        
    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        #extract the fields
        packet_type = int(byte_S[Packet.length_S_length: Packet.length_S_length + Packet.packet_type_length])
        seq_num = int(byte_S[Packet.length_S_length + Packet.packet_type_length : Packet.length_S_length +Packet.packet_type_length +Packet.seq_num_S_length])
        msg_S = byte_S[Packet.length_S_length+Packet.packet_type_length + Packet.seq_num_S_length+Packet.checksum_length :]
        return self(packet_type, seq_num, msg_S)
        
        
    def get_byte_S(self):
        packet_type_S = str(self.packet_type)
        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(packet_type_S) + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(self.length_S_length)
        #compute the checksum
        checksum = hashlib.md5((length_S+packet_type_S+seq_num_S+self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return length_S + packet_type_S + seq_num_S + checksum_S + self.msg_S
   
    
    @staticmethod
    def corrupt(byte_S):
        #extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        packet_type_S = byte_S[Packet.length_S_length : Packet.length_S_length + Packet.packet_type_length]
        seq_num_S = byte_S[Packet.length_S_length +Packet.packet_type_length : Packet.seq_num_S_length+Packet.packet_type_length+Packet.seq_num_S_length]
        checksum_S = byte_S[Packet.seq_num_S_length+Packet.packet_type_length+Packet.seq_num_S_length : Packet.seq_num_S_length+Packet.packet_type_length+Packet.length_S_length+Packet.checksum_length]
        msg_S = byte_S[Packet.seq_num_S_length+Packet.packet_type_length+Packet.seq_num_S_length+Packet.checksum_length :]
        
        #compute the checksum locally
        checksum = hashlib.md5(str(length_S+packet_type_S+seq_num_S+msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        #and check if the same
        return checksum_S != computed_checksum_S
        

class RDT:
    ## latest sequence number used in a packet
    seq_num = 0
    ## buffer of bytes read from network
    byte_buffer = '' 
    retransmit_MSG = '' 

    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)
    
    def disconnect(self):
        self.network.disconnect()
        
    def rdt_1_0_send(self, msg_S):
        p = Packet(1, self.seq_num, msg_S)
        self.seq_num += 1
        self.network.udt_send(p.get_byte_S())
        
    def rdt_1_0_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
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
            print(str(p.packet_type))
            #remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            #if this was the last packet, will return on the next iteration
            
    
    def rdt_2_1_send(self, msg_S):
        self.retransmit_MSG = msg_S #reassign the retransimit message to the current one
        p = Packet(self.seq_num, self.seq_num, msg_S)
        self.network.udt_send(p.get_byte_S())
        
    def rdt_2_1_receive(self):
        ret_S = None
        byte_S = None
        p_type = None
        p_seq = None
        corrupt = False

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
                p_type = p.packet_type
                p_seq = p.seq_num
                ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                self.byte_buffer = self.byte_buffer[length:]
            except Exception as e:
                ret_S = "CORRUPT"
                print ("Exception: "+str(e))
                corrupt = True
                break
        if ret_S == None:
            return None

        print("P Type: "+str(p_type))
        #packet is corrupt
        if corrupt:
            print("Packet is corrupt with self.seq_num: "+str(self.seq_num))
            #send a NAK
            p = Packet(2, self.seq_num, "2")       
            self.network.udt_send(p.get_byte_S())
            sleep(1)
            return None
        #it's text (new)
        elif(p_type == 0 and p_seq == self.seq_num): 
            print("New text received, sending ACK and transmittint up to APP layer with p.seq_num: "+str(p_seq)+ " self.seq_num: "+str(self.seq_num))
            #send ACK
            p = Packet(1, self.seq_num, "1")       
            self.network.udt_send(p.get_byte_S())
            self.seq_num = 1 if self.seq_num == 0 else 0
            #send to APP layer
            return ret_S                          
        #it's text and from previous communication cycle
        elif(p_type == 0 and p_seq != self.seq_num): 
            print("Old text received, resending an ACK with p.seq_num: "+str(p_seq)+ " self.seq_num: "+str(self.seq_num))
            #send another ACK
            p = Packet(1, self.seq_num, "1")       
            self.network.udt_send(p.get_byte_S())
            #don't send up to APP layer
            return None                           
        #it's an ACK
        elif(p_type == 1):
            print("ACK received, switching seq num states with p.seq_num: "+str(p_seq)+ " self.seq_num: "+str(self.seq_num))
            self.seq_num= 1 if self.seq_num == 0 else 0
            return None
        #it's a NAK, p_type == 2
        else:
            print("NAK received, retransmitting with p.seq_num: "+str(p_seq)+ " self.seq_num: "+str(self.seq_num))
            #send them the old message again
            #if p_seq == self.seq_num:              
            self.rdt_2_1_send(self.retransmit_MSG)
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
        


        
        
