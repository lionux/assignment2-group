import Network
import argparse
from time import sleep
import hashlib
import sys
import os

class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    send_state_S_length = 1
    recv_state_S_length = 1
    length_S_length = 10
    packet_type_length = 1
    ## length of md5 checksum in hex
    checksum_length = 32 
        
    def __init__(self, packet_type, send_state, recv_state, seq_num, msg_S):
        self.packet_type = packet_type
        self.recv_state = recv_state
        self.send_state = send_state
        self.seq_num = seq_num
        self.msg_S = msg_S
        
    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        #extract the fields
        packet_type = int(byte_S[Packet.length_S_length: Packet.length_S_length + Packet.packet_type_length])
        send_state = int(byte_S[Packet.length_S_length + Packet.packet_type_length : Packet.length_S_length +Packet.packet_type_length +Packet.send_state_S_length])
        recv_state = int(byte_S[Packet.length_S_length + Packet.packet_type_length + Packet.send_state_S_length: Packet.length_S_length +Packet.packet_type_length +Packet.send_state_S_length + Packet.recv_state_S_length])
        seq_num = int(byte_S[Packet.length_S_length + Packet.packet_type_length +Packet.send_state_S_length + Packet.recv_state_S_length: Packet.length_S_length +Packet.packet_type_length +Packet.send_state_S_length + Packet.recv_state_S_length+Packet.seq_num_S_length])
        msg_S = byte_S[Packet.length_S_length+Packet.packet_type_length + Packet.seq_num_S_length+Packet.send_state_S_length + Packet.recv_state_S_length+Packet.checksum_length :]
        return self(packet_type, send_state, recv_state, seq_num, msg_S)
        
        
    def get_byte_S(self):
        packet_type_S = str(self.packet_type)
        send_state_S = str(self.send_state)
        recv_state_S = str(self.recv_state)
        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(packet_type_S) + len(send_state_S) + len(recv_state_S) + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(self.length_S_length)
        #compute the checksum
        checksum = hashlib.md5((length_S+packet_type_S+send_state_S+recv_state_S+ seq_num_S+self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return length_S + packet_type_S + send_state_S + recv_state_S + seq_num_S + checksum_S + self.msg_S
   
    
    @staticmethod
    def corrupt(byte_S):
        #extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        packet_type_S = byte_S[Packet.length_S_length : Packet.length_S_length + Packet.packet_type_length]
        send_state_S = byte_S[Packet.length_S_length + Packet.packet_type_length : Packet.length_S_length + Packet.packet_type_length + Packet.send_state_S_length]
        recv_state_S = byte_S[Packet.length_S_length + Packet.packet_type_length + Packet.send_state_S_length : Packet.length_S_length + Packet.packet_type_length + Packet.send_state_S_length + Packet.recv_state_S_length]
        seq_num_S = byte_S[Packet.length_S_length +Packet.packet_type_length+ Packet.send_state_S_length + Packet.recv_state_S_length : Packet.seq_num_S_length+Packet.packet_type_length+ Packet.send_state_S_length + Packet.recv_state_S_length+Packet.seq_num_S_length]
        checksum_S = byte_S[Packet.seq_num_S_length+Packet.packet_type_length+ Packet.send_state_S_length + Packet.recv_state_S_length+Packet.seq_num_S_length : Packet.seq_num_S_length+Packet.packet_type_length+ Packet.send_state_S_length + Packet.recv_state_S_length+Packet.length_S_length+Packet.checksum_length]
        msg_S = byte_S[Packet.seq_num_S_length+Packet.packet_type_length+ Packet.send_state_S_length + Packet.recv_state_S_length+Packet.length_S_length+Packet.checksum_length :]
        #compute the checksum locally
        checksum = hashlib.md5(str(length_S+packet_type_S+send_state_S+recv_state_S+seq_num_S+msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        #and check if the same
        return checksum_S != computed_checksum_S
        

class RDT:
    ## latest sequence number used in a packet
    #note that for 2_1 this is used as the recv state (it's either 0 or 1)
    seq_num = 0
    #the NAK send state (either 0 or 1), for 2_1
    our_send_state = 0
    our_recv_state = 0
    rct_NAK = 0 #set to 1 if a NAK was the last msg sent
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
        p = Packet(0, self.our_send_state, self.our_recv_state, self.seq_num, msg_S)
        self.network.udt_send(p.get_byte_S())
        sleep(1)
        
    def rdt_2_1_receive(self):
        ret_S = None
        byte_S = None
        p_type = None
        p_seq = None
        p_recv_state = None
        p_send_state = None
        corrupt = False
        byte_S = self.network.udt_receive()
        #print("RECEIVED PACKET: "+str(byte_S))
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
                p_recv_state = p.recv_state
                p_send_state = p.send_state
                ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                self.byte_buffer = self.byte_buffer[length:]
            except Exception as e:
                self.byte_buffer = ''
                ret_S = "CORRUPT"
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                print(exc_type, fname, exc_tb.tb_lineno)
                print(e)
                corrupt = True
                break
        if ret_S == None:
            return None
        print("\n\nPACKET: "+str(byte_S)+"\n")
        #packet is corrupt
        if corrupt:
            print("Packet is corrupt, SENDING NAK")
            self.rct_NAK = 1
            #send a NAK
            p = Packet(2, self.our_send_state, self.our_recv_state, self.seq_num, "NAK")       
            self.network.udt_send(p.get_byte_S())
            sleep(1)
            return None
        #it's text (new)
        elif(p_type == 0 and p_recv_state == self.our_send_state): 
            print("New text received, sending ACK and transmitting up to APP layer with p_recv_state: "+str(p_recv_state)+ " self.our_send_state: "+str(self.our_send_state))
            #send ACK
            self.rct_NAK = 0
            p = Packet(1, self.our_send_state, self.our_recv_state, self.seq_num, "ACK")       
            self.network.udt_send(p.get_byte_S())
            #change both our send and recv states
            self.our_recv_state = 1 if self.our_recv_state == 0 else 0
            sleep(1)
            #send to APP layer
            return ret_S                          
        #it's text and from previous communication cycle
        elif(p_type == 0 and p_recv_state != self.our_send_state): 
            print("Old text received, resending an ACK with p_recv_state: "+str(p_recv_state)+ " self.our_send_state: "+str(self.our_send_state))
            #send another ACK
            self.rct_NAK = 0
            p = Packet(1, self.our_send_state, self.our_recv_state, self.seq_num, "ACK")       
            #self.network.udt_send(p.get_byte_S())
            sleep(1)
            #don't send up to APP layer
            return None                           
        #it's an ACK
        elif(p_type == 1):
            print("ACK received, switching our send state, p_recv_state: "+str(p_recv_state)+ " self.our_send_state: "+str(self.our_send_state))
            self.our_send_state = 1 if self.our_send_state == 0 else 0
            sleep(1)
            return None
        #it's a NAK, p_type == 2
        else:
            print("NAK received, retransmitting with p_recv_state: "+str(p_recv_state)+ " self.our_send_state: "+str(self.our_send_state))
            if self.our_recv_state == p_send_state:
                print("Sending data again")
                self.seq_num = p_seq
                self.rdt_2_1_send(self.retransmit_MSG)
            else:
                print("Sending another ACK")
                p = Packet(1, self.our_send_state, self.our_recv_state, self.seq_num, "ACK")       
                self.network.udt_send(p.get_byte_S())

            # #the packet was an ACK that was lost
            # if self.our_recv_state != p_send_state:
            #     print("Sending another ACK, since an ACK was lost")
            #     p = Packet(1, p_recv_state, self.our_recv_state, self.seq_num, "ACK")       
            #     self.network.udt_send(p.get_byte_S())
            # #we know that a NAK wasn't lost, it was either a NAK or a msg
            # else:
            #     if self.rct_NAK == 1:
            #         "Actually send NAK again because our NAK must have been lost"
            #         p = Packet(2, self.our_send_state, self.our_recv_state, self.seq_num, "NAK")       
            #         self.network.udt_send(p.get_byte_S())
            #     else:
            #         print("Actually send msg again because seq nums are equal")
            #         self.seq_num = p_seq   
            #         self.rdt_2_1_send(self.retransmit_MSG)



            #send them the old message again
            # if self.our_send_state != p_send_state: 
            #     print("Don't do anything because it must have been an ACK that was Corrupt")
            #     #print("Actually send ACK again")
            #     #self.seq_num = p_seq           
            #     #p = Packet(1, self.seq_num, "ACK")     
            #     #self.udt_send(p.get_byte_S())
            # elif self.our_send_state == p_send_state and self.our_recv_state == p_recv_state:
            #     if self.rct_NAK == 1:
            #         "Actually send NAK again because our NAK must have been lost"
            #         p = Packet(2, self.our_send_state, self.our_recv_state, self.seq_num, "NAK")       
            #         self.network.udt_send(p.get_byte_S())
            #     else:
            #         print("Actually send msg agian because seq nums are equal")
            #         self.seq_num = p_seq   
            #         self.rdt_2_1_send(self.retransmit_MSG)

            sleep(1)
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
        


        
        
