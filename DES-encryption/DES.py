from PBox import *
from SBox import *

class DES:
    def __init__(self, key):
        self.key = key
        self.round_keys = self.generate_round_keys()
        self.p_initial = ip_table
    
    @staticmethod
    def encrypt(msg):
        binary_rep_of_input = DES.str_to_bin(msg)
        ip_result_str = DES.ip_on_binary_rep(binary_rep_of_input)

        lpt = ip_result_str[:32]
        rpt = ip_result_str[32:]

        new_lpt, new_rpt = DES.rounds(lpt, rpt)
        final_result = new_rpt + new_lpt

        final_cipher = DES.ip_inverse(final_result)
        final_cipher_str = ''.join(final_cipher)

        final_cipher_ascii = DES.binary_to_ascii(final_cipher_str)
        return final_cipher_ascii

    def ip_inverse(final_result):
        final_cipher = [final_result[ip_inverse_table[i] - 1] for i in range(64)] 
        return final_cipher
        
    def rounds(self, lpt, rpt):

        for round_key in self.round_keys:
            expanded_result = DES.expasion_permutation(rpt)
            # Convert the result back to a string for better visualization
            expanded_result_str = ''.join(expanded_result)

            xor_result_str = DES.first_xor(expanded_result_str, round_key)

            s_box_substituted = DES.s_box_substitution(xor_result_str)

            p_box_result = DES.p_box_permutation(s_box_substituted)

            new_rpt = DES.second_xor(lpt, p_box_result) 
            # Convert the result back to a string for better visualization
            new_rpt_str = ''.join(new_rpt)

            # Update LPT and RPT for the next round
            lpt = rpt
            rpt = new_rpt_str

        return lpt, rpt

    def second_xor(lpt, p_box_result):
        
        # Convert LPT to a list of bits for the XOR operation
        lpt_list = list(lpt)

        # Perform XOR operation
        new_rpt = [str(int(lpt_list[i]) ^ int(p_box_result[i])) for i in range(32)]

        return new_rpt

    def p_box_permutation(s_box_substituted):
        p_box_result = [s_box_substituted[i - 1] for i in p_box_table]
        return p_box_result
            
    def s_box_substitution(xor_result_str):
        # Split the 48-bit string into 8 groups of 6 bits each
        six_bit_groups = [xor_result_str[i:i+6] for i in range(0, 48, 6)]

        # Initialize the substituted bits string
        s_box_substituted = ''

        # Apply S-box substitution for each 6-bit group
        for i in range(8):
            # Extract the row and column bits
            row_bits = int(six_bit_groups[i][0] + six_bit_groups[i][-1], 2)
            col_bits = int(six_bit_groups[i][1:-1], 2)

            # Lookup the S-box value
            s_box_value = s_boxes[i][row_bits][col_bits]
            
            # Convert the S-box value to a 4-bit binary string and append to the result
            s_box_substituted += format(s_box_value, '04b')
        
        return s_box_substituted


    def first_xor(expanded_result_str, round_key):   
        xor_result_str = ''

        for i in range(48):
            xor_result_str += str(int(expanded_result_str[i]) ^ int(round_key[i]))
        
        return xor_result_str

    
    def expasion_permutation(rpt):
        expanded_result = [rpt[i - 1] for i in e_box_table]
        return expanded_result
    

    def generate_round_keys(self):
        binary_representation_key = self.key_in_binary_conv()
        pc1_key_str = ''.join(binary_representation_key[bit - 1] for bit in pc1_table)

        c, d = pc1_key_str[:28], pc1_key_str[28:]
        for shift in (shift_schedule):
            c = c[shift:] + c[:shift]
            d = d[shift:] + d[:shift]
            cd = c + d
            round_key = ''.join(cd[bit - 1] for bit in pc2_table)
            self.round_keys.append(round_key)
        return
    
    def ip_on_binary_rep(self, binary_representation):
        ip_result = [None] * 64
        
        for i in range(64):
            ip_result[i] = binary_representation[self.p_initial[i] - 1]

        # Convert the result back to a string for better visualization
        ip_result_str = ''.join(ip_result)
        
        return ip_result_str

    def str_to_bin(msg : str):
    
        # Convert the string to binary
        binary_representation = ''
        
        for char in msg:
            # Get ASCII value of the character and convert it to binary
            binary_char = format(ord(char), '08b')
            binary_representation += binary_char
            binary_representation = binary_representation[:64]
        
        # Pad or truncate the binary representation to 64 bits
        binary_representation = binary_representation[:64].ljust(64, '0')
        
        return binary_representation

    def key_in_binary_conv(self):
        # Original key (can be changed but it should be 8 char)
        original_key = self.key
        binary_representation_key = ''
        
        for char in original_key:
        # Convert the characters to binary and concatenate to form a 64-bit binary string
            binary_key = format(ord(char), '08b') 
            binary_representation_key += binary_key

        return binary_representation_key
    
    def binary_to_ascii(binary_str):
        ascii_str = ''.join([chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8)])
        return ascii_str

