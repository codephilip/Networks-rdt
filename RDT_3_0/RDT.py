import Network
import argparse
from time import sleep
import hashlib

class RDTException(Exception):
    pass

class Packet:
    # the number of bytes used to store packet length
    seq_num_S_length = 20
    length_S_length = 20
    # length of md5 checksum in hex
    checksum_length = 32 

    def __init__(self, seq_num, msg_S, ack):
        self.seq_num = seq_num
        self.msg_S = msg_S
        self.ack_status = ack 

    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            return self(None,None,False) #Nada
        seq_num = int(byte_S[Packet.length_S_length : Packet.length_S_length+Packet.seq_num_S_length])
        msg_S = byte_S[Packet.length_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        return self(seq_num, msg_S, True) # ack is correct

    def get_byte_S(self):
        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(self.length_S_length)
        #compute the checksum
        checksum = hashlib.md5((length_S+seq_num_S+self.msg_S).encode('utf-8'))
        checksum_hex = checksum.hexdigest()
        #compile into a string
        return length_S + seq_num_S + checksum_hex + self.msg_S


    @staticmethod
    def corrupt(byte_S):
        #extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length : Packet.seq_num_S_length+Packet.seq_num_S_length]
        checksum_hex = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length : Packet.seq_num_S_length+Packet.length_S_length+Packet.checksum_length]
        msg_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        #compute the checksum 
        checksum = hashlib.md5(str(length_S+seq_num_S+msg_S).encode('utf-8'))
        computed_checksum_hex = checksum.hexdigest()
        return checksum_hex != computed_checksum_hex


class RDT:

    seq_num = 0
    byte_buffer = ''
    def __init__(self, role_S, server_S, port):
        #older version (didnt follow port and port+1)
        self.network = Network.NetworkLayer(role_S, server_S, port)
    
    def disconnect(self):
        self.network.disconnect()
    

    def seq_num_alt(seq_num):
        if seq_num == 0:
            seq_num = 1
        elif seq_num == 1:
            seq_num = 0
        else:
            print("**Sequence Number ERROR**")
        return seq_num

    def rdt_3_0_send(self, msg_S):
        p = Packet(self.seq_num, msg_S, None)
        
        while True:
            self.network.udt_send(p.get_byte_S()) # send packet (udt)
            r = ""

            while r == "":
                self.network.udt_send(p.get_byte_S())
                sleep(1)
                r = self.network.udt_receive()

            message_length = int(r[:Packet.length_S_length])
            self.byte_buffer = r[message_length:]
            ack_packet = Packet.from_byte_S(r[:message_length])

            #if packet correct:
            if ack_packet.ack_status: 

                if ack_packet.seq_num == self.seq_num and ack_packet.msg_S == "0": 
                    print("**Received ACK**")
                    print("seq_num: ", ack_packet.seq_num, "\n")
                    self.seq_num = RDT.seq_num_alt(self.seq_num) #update with alternationFunct / %2
                    break

                elif ack_packet.seq_num == self.seq_num and ack_packet.msg_S == "1": 
                    print("**Received NACK**")
                    print("seq_num: ", ack_packet.seq_num, "\n")
                    self.byte_buffer = ""

                else:
                    timeout = True
                    print("**TIMEOUT**")
                    actual_packet = ack_packet 
                    print("seq_num:", ack_packet.seq_num, "\n")

                    if actual_packet.ack_status:
                        #send ACK
                        ack_packet = Packet(actual_packet.seq_num, "0", None) 
                        self.network.udt_send(ack_packet.get_byte_S())

                    elif not actual_packet.ack_status:
                        #send NACK
                        ack_packet = Packet(actual_packet.seq_num, "1", None) 
                        self.network.udt_send(ack_packet.get_byte_S())

                    self.byte_buffer = ""
            #corrupt package: 
            else: 
                print("Packet is CORRUPT.")
                print("seq_num: ", ack_packet.seq_num)
                self.byte_buffer = ""



    def rdt_3_0_receive(self):

        response_msg = None 
        msg =""

        while msg =="":
            msg = self.network.udt_receive() 

        self.byte_buffer += msg # add to buffer

        while True: 

            if(len(self.byte_buffer) < Packet.length_S_length):
                break

            length = int(self.byte_buffer[:Packet.length_S_length])

            #check length : length giving me problems?
            if len(self.byte_buffer) < length: 
                break

            print("------Received a packet!-------")
            p = Packet.from_byte_S(self.byte_buffer[0:length])

            #CORRUPT:
            if not p.ack_status: 

                print("**Sending NACK** - Packet is CORRUPT.\n")
                print("Sequence number: ", p.seq_num)
                ack_packet = Packet(p.seq_num, "1", None)
                self.network.udt_send(ack_packet.get_byte_S())
                msg =""

                while msg =="":
                    msg = self.network.udt_receive() 

                self.byte_buffer = ""
                self.byte_buffer += msg

                if(len(self.byte_buffer) < Packet.length_S_length): 
                    break

                length = int(self.byte_buffer[:Packet.length_S_length])

                if len(self.byte_buffer) < length: 
                    break
                
                p = Packet.from_byte_S(self.byte_buffer[0:length])

            else:
                print("Packet is CORRECT - no corruption.\n")

                #Changing States - Error
                if p.msg_S == "0" or p.msg_S == "1":
                    self.byte_buffer = self.byte_buffer[length:]
                    continue

                else : # checking seq_num
                    print("**Sending ACK** - Packet AS EXPECTED. .")
                    ack_packet = Packet(p.seq_num, "0", None)
                    self.network.udt_send(ack_packet.get_byte_S())
                    #self.seq_num = RDT.seq_num_alt(self.seq_num)
                    break

        try:
            p
        except NameError:
            p = None
        if p is None:
            return None
            
        response_msg = p.msg_S if (response_msg is None) else response_msg + p.msg_S
        return response_msg

if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()

    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_3_0_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_3_0_receive())
        rdt.disconnect()


    else:
        sleep(1)
        print(rdt.rdt_3_0_receive())
        rdt.rdt_3_0_send('MSG_FROM_SERVER')
        rdt.disconnect()