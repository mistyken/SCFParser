import sys
import os
import copy


def parse_tlv(tlv_file):
    bm_type_header_no_data = [bytes(b'\x03'), bytes(b'\x07'), bytes(b'\x09'), bytes(b'\x0a'),
                              bytes(b'\x0b')]
    bm_type_header_with_data = [bytes(b'\x01'), bytes(b'\x02'), bytes(b'\x04'), bytes(b'\x05'), bytes(b'\x06'),
                           bytes(b'\x08'), bytes(b'\x0c'), bytes(b'\x0e')]

    def process_value_captured(data_dict, field_type):
        if field_type == bytes(b'\x02'):
            holder = bytes()
            nonlocal header_length
            for v in data_dict[field_type]:
                holder += v
            value = int.from_bytes(holder, byteorder='big')
            header_length = value
            return value
        return data_dict[field_type]

    if os.path.isfile(tlv_file):
        file_size = os.path.getsize(tlv_file)
        print("This is a file. file size is: {} bytes")
        bytes_array = []
        int_array = []

        header_data_dict = {}

        with open(tlv_file, "rb") as f:
            bytes_read = f.read(1)
            header_length = file_size
            bytes_index = 1

            field_type = ''
            length_count = 0
            length = 0
            length_holder = []
            while bytes_read != b"" and bytes_index < header_length:
                #this boolean ensure that we only do 1 action per bytes read from the file
                work_done = False
                bytes_array.append(bytes_read)
                int_array.append(int.from_bytes(bytes_read, byteorder='big'))

                #start processing the field value once we have the length
                if length > 0 and not work_done:
                    work_done = True
                    header_data_dict[field_type].append(bytes_read)
                    length -= 1
                    if length < 1:
                        header_data_dict[field_type] = process_value_captured(header_data_dict, field_type)

                #start working on getting the field length
                if length_count > 0 and not work_done:
                    work_done = True
                    length_holder.append(bytes_read)
                    length_count -= 1
                    #field length of 2 bytes is captured. start processing the length bytes into int
                    if length_count < 1:
                        #this is one of the field type that contains just value
                        if field_type in bm_type_header_no_data:
                            header_data_dict[field_type] = copy.deepcopy(length_holder)
                            header_data_dict[field_type] = process_value_captured(header_data_dict, field_type)
                            bm_type_header_no_data.remove(field_type)
                            length_holder.clear()
                        else:
                            length = int.from_bytes(length_holder[0] + length_holder[1], byteorder='big')
                            length_holder.clear()

                #check if the current bytes is a field type
                if (bytes_read in bm_type_header_with_data or bytes_read in bm_type_header_no_data) and not work_done:
                    #length is 2 bytes. set length counter to 2. initiating type list to prep for incoming data
                    length_count = 2
                    field_type = bytes_read
                    header_data_dict[field_type] = []

                    #field type found, removing found type from type list...if it's one that has no data content
                    if bytes_read in bm_type_header_with_data:
                        bm_type_header_with_data.remove(field_type)

                bytes_read = f.read(1)
                bytes_index += 1

if __name__ == "__main__":
    parse_tlv(sys.argv[1])
