import Network
import argparse
from time import sleep
import hashlib

class RDTException(Exception):
    pass

class Packet:
    # the number of bytes used to store packet length
    seq_num_S_length = 10 
    length_S_length = 10 
    # length of md5 checksum in hex
    checksum_length = 32 

    def __init__(self, seq_num, msg_S, ack):
        self.seq_num = seq_num
        self.msg_S = msg_S
        self.ack_status = ack 

    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            return self(None, None, False) 
        #extract the fields
        seq_num = int(byte_S[Packet.length_S_length : Packet.length_S_length+Packet.seq_num_S_length])
        msg_S = byte_S[Packet.length_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        return self(seq_num, msg_S, True) 

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
        #compute the checksum locally
        checksum = hashlib.md5(str(length_S+seq_num_S+msg_S).encode('utf-8'))
        computed_checksum_hex = checksum.hexdigest()
        #and check if the same
        return checksum_hex != computed_checksum_hex


class RDT:

    seq_num = 0 
    byte_buffer = ''

    def __init__(self, role_S, server_S, port):
        #old --ver
        self.network = Network.NetworkLayer(role_S, server_S, port)

    def disconnect(self):
        self.network.disconnect()

    def rdt_2_1_send(self, msg_S):

        p = Packet(self.seq_num, msg_S, None)
        initial_seq = self.seq_num
        print("seq_num: ", self.seq_num%2)

        while initial_seq == self.seq_num:
            self.network.udt_send(p.get_byte_S())
            r = ''

            while r == '':
                r = self.network.udt_receive()

            msg_length = int(r[:Packet.length_S_length])
            self.byte_buffer = r[msg_length:]

            if not Packet.corrupt(r[:msg_length]):
                print("Packet is NOT corrupt.")
                res_p = Packet.from_byte_S(r[:msg_length])

                if res_p.seq_num < self.seq_num:
                    acknowledgment_packet = Packet(res_p.seq_num, "1", None)
                    self.network.udt_send(acknowledgment_packet.get_byte_S())

                if res_p.msg_S == "1":
                    self.seq_num += 1
                    print("**ACK Received**")
                    print("seq_num: ", self.seq_num%2)

                elif res_p.msg_S == "0":
                    self.byte_buffer = ''
                    print("**NACK received**")
                    print("seq_num: ", self.seq_num%2)
            else:
                self.byte_buffer = ''
                print("Packet is CORRUPT.")

    def rdt_2_1_receive(self):

        response_msg = None
        msg = self.network.udt_receive()
        self.byte_buffer += msg
        initial_seq_num = self.seq_num

        while initial_seq_num == self.seq_num:

            if len(self.byte_buffer) < Packet.length_S_length:
                break

            length = int(self.byte_buffer[:Packet.length_S_length])

            if len(self.byte_buffer) < length:
                break

            if Packet.corrupt(self.byte_buffer):
                # Send a NAK
                print("**Sending NACK** - Packet is CORRUPT.\n")
                r = Packet(self.seq_num, "0", None)
                self.network.udt_send(r.get_byte_S())

            else:
                p = Packet.from_byte_S(self.byte_buffer[0:length])

                if p.msg_S == '1' or p.msg_S == '0':
                    print("Staying in same state.")
                    self.byte_buffer = self.byte_buffer[length:]
                    continue

                else:
                    print("**Sending ACK** - Packet AS EXPECTED...")
                    r = Packet(self.seq_num, "1", None)
                    self.network.udt_send(r.get_byte_S())
                    self.seq_num += 1

                response_msg = p.msg_S if (response_msg is None) else response_msg + p.msg_S

            self.byte_buffer = self.byte_buffer[length:]

        return response_msg

if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()

    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_2_1_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_2_1_receive())
        rdt.disconnect()


    else:
        sleep(1)
        print(rdt.rdt_2_1_receive())
        rdt.rdt_2_1_send('MSG_FROM_SERVER')
        rdt.disconnect()