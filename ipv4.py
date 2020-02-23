import sys, re, json

class IPV4:

    def __init__(self, input_string):

        if type(input_string).__name__ == 'str':

            if re.search(r'list', input_string):
                list_mode = True
            else:
                list_mode = False

            if re.search('/',input_string):
                delimiter='/'
                split = input_string.split(delimiter)
                ipv4_address = split[0]
                subnet_mask = split[1]
            elif re.search(' ',input_string):
                delimiter=' '
                split = input_string.split(delimiter)
                ipv4_address = split[0]
                subnet_mask = split[1]
            else:
                ipv4_address = input_string
                subnet_mask = '32'


        if int(subnet_mask) <= 32:
            is_cidr = True
        else:
            is_cidr = False

        if is_cidr == True:
            self.mask_cidr = subnet_mask
            self.mask_octet = self.find_classfull_mask(self.mask_cidr)

        elif is_cidr == False:
            self.mask_octet = subnet_mask
            self.mask_cidr = self.find_classless_mask(self.mask_octet)


        self.bits_net = int(self.mask_cidr)
        self.bits_host = 32 - int(self.mask_cidr)

        self.ip_addr = ipv4_address

        # IP Address

        addr_bin_and_valid_ip =  self.is_valid_ip(self.ip_addr)
        self.bin_addr = addr_bin_and_valid_ip[0]
        self.bin_addr_f = addr_bin_and_valid_ip[1]
        self.is_valid_ip = addr_bin_and_valid_ip[2]

        if not addr_bin_and_valid_ip[2]:
            raise Exception(f'Invalid IPv4 Address format'
                            f' - ({ipv4_address})')

        # Mask

        mask_binary_and_valid_check = self.is_valid_mask(self.mask_octet)

        self.bin_mask = mask_binary_and_valid_check[0]
        self.bin_mask_f = mask_binary_and_valid_check[1]
        self.is_ip_mask = self.is_valid_mask(self.ip_addr)[2]
        self.is_valid_mask = mask_binary_and_valid_check[2]
        self.is_ip_broadcast = self.is_broadcast(self.ip_addr)

        if not mask_binary_and_valid_check[1]:
            raise Exception(f'Invalid Subnet Mask format'
                            f' - ({subnet_mask})')

        self.type = self.find_type(self.ip_addr)
        self.p2p = self.is_p2p(self.bits_host)

        # Totals

        t_addresses_t_hosts = self.find_total_hosts(self.bits_host)
        self.total_addresses =  t_addresses_t_hosts[0]
        self.total_hosts = t_addresses_t_hosts[1]

        # Network info

        self.ip_net_id = self.find_network_id(self.ip_addr,\
                                            self.mask_cidr)

        first_last_bcast = self.first_and_last_address(self.ip_net_id,\
                                                        self.ip_addr)
        self.ip_first_address = first_last_bcast[0]
        self.ip_last_address = first_last_bcast[1]
        self.ip_broadcast_address = first_last_bcast[2]

        if list_mode == True:
            self.address_list = self.list_all_addresses(self.net_id,\
                                                        self.first_address,\
                                                        self.last_address)

    def find_total_hosts(self,host_bits):
        total_hosts=0

        #Any subnet greater than a /32 or /31
        if host_bits > 1:
            for i in range(host_bits):
                total_hosts=pow(2,i+1)
            return(total_hosts,total_hosts-2)

        #Single host (/32)
        elif host_bits == 0:
            total_hosts+=1
            return(total_hosts,total_hosts)

        #Point to point (/31)
        elif host_bits == 1:
            total_hosts+=2
            return(total_hosts,total_hosts)

        #Any other mask
        else:
            return(total_hosts,total_hosts-2)

    def is_p2p(self,host_bits):
        if host_bits <= 1:
            return True
        else:
            return False

    def is_broadcast(self,ipv4_address):
        addr=ipv4_address.split('.')
        total=0
        for i in range(len(addr)):
            total+=int(addr[i])
        if total == 1020:
            return True
        else:
            return False

    def is_valid_ip(self,ipv4_address):
        ip_binary=[]
        format_ip_binary=[]
        valid_octet=0
        is_valid_ip=False
        addr=ipv4_address.split('.')
        for i in range(len(addr)):
            ip_binary.append(str(bin(int(addr[i]))))
            ip_binary[i]=ip_binary[i][2:]
            format_ip_binary.append(str(bin(int(addr[i]))))
            format_ip_binary[i]=ip_binary[i][2:]
            if int(addr[i]) <= 255:
                valid_octet+=1
            while len(format_ip_binary[i])<8:
                format_ip_binary[i]+='o'
            if i % 1 == 0:
                format_ip_binary[i]+=' '
        format_ip_binary=''.join(format_ip_binary)
        ip_binary=''.join(ip_binary)
        if valid_octet==4:
            is_valid_ip=True

        return(ip_binary,\
               format_ip_binary,\
               is_valid_ip)

    def is_valid_mask(self, mask_addr):
        valid_bits = re.compile(r'(^[1]+[0]+$|^\d[1]+$)')

        mask_binary=[]
        is_valid_mask=False
        addr = mask_addr.split('.')
        for i in range(len(addr)):
            mask_binary.append(str(bin(int(addr[i]))))
            mask_binary[i]=mask_binary[i][2:]

        format_mask_binary=' '.join(mask_binary)
        mask_binary=''.join(mask_binary)


        if len(mask_binary) in [11,18,25,32] and re.match(valid_bits,mask_binary):
            is_valid_mask=True

        elif mask_addr in range(1,32):
            is_valid_mask=True


        while len(mask_binary)<32:
            mask_binary+='0'
        while len(format_mask_binary)<35:
            format_mask_binary+='0'


        return(mask_binary,\
               format_mask_binary,\
               is_valid_mask)

    def find_classless_mask(self,mask):
        mask_bits=0
        mask = mask.split('.')
        for octet in mask:
            for i in bin(int(octet)):
                if i == '1':
                    mask_bits+=1
        return mask_bits

    def find_classfull_mask(self,mask_bits):
        classfull_mask_bin = []
        classfull_mask_int = []
        mask_octet=''
        for count in range(1,33):

            if count <= int(mask_bits):
                mask_octet+='1'
            else:
                mask_octet+='0'

            if count % 8 == 0:
                classfull_mask_bin.append(mask_octet)
                classfull_mask_int.append(str(int(mask_octet, 2)))
                mask_octet=''

        return '.'.join(classfull_mask_int)

    def list_all_addresses(self,net_id,first_add,last_add):
        address_list=[]

        address_list.append(first_add)
        current_add = first_add.split('.')

        if self.total_addresses == 256:
            host_count = self.total_hosts
        if self.total_addresses > 256:
            host_count = self.total_hosts
        if self.total_addresses < 256:
            host_count = self.total_hosts

        for octet in range(len(current_add)):
            current_add[octet]=int(current_add[octet])
        octet=3
        mod=1


        if host_count < 254:
            for count in range(host_count-1):
                current_add[octet]=int(current_add[octet])+1
                for i_octet in range(len(current_add)):
                    current_add[i_octet]=str(current_add[i_octet])
                address_list.append(str('.'.join(current_add)))

        if host_count == 254:
            for count in range(host_count-1):
                if count % 255 == 0 and count != 0:
                    current_add[octet-mod]=int(current_add[octet-mod])+1
                    current_add[octet]=0
                else:
                    current_add[octet]=int(current_add[octet])+1

                for i_octet in range(len(current_add)):
                    current_add[i_octet]=str(current_add[i_octet])
                address_list.append(str('.'.join(current_add)))

        if host_count > 254:
            for count in range(host_count+1):

                if count % 256 == 0 and count != 0:

                    current_add[octet-1]=int(current_add[octet-1])+1
                    current_add[octet]=0

                    if current_add[octet-1]==256:
                        current_add[octet-2]=int(current_add[octet-2])+1
                        current_add[octet-1]=0
                        current_add[octet]=0

                    if current_add[octet-2]==256:
                        current_add[octet-3]=int(current_add[octet-3])+1
                        current_add[octet-2]=0
                        current_add[octet]=0

                    if current_add[octet-3]==256:
                        current_add[octet-4]=int(current_add[octet-4])+1
                        current_add[octet-3]=0
                        current_add[octet]=0

                else:
                    current_add[octet]=int(current_add[octet])+1

                for i_octet in range(len(current_add)):
                    current_add[i_octet]=str(current_add[i_octet])
                address_list.append(str('.'.join(current_add)))

        return address_list

    def first_and_last_address(self,net_id,supplied_ip):

        addr=net_id.split('.')

        if self.bits_host == 0:
            broadcast_address=net_id
            first_address=net_id
            last_address=net_id
            return first_address,last_address,broadcast_address

        if self.bits_host == 1:
            broadcast_address=None
            first_address=supplied_ip
            addr[3] = str(int(addr[3])+1)
            last_address='.'.join(addr)
            return first_address,last_address,broadcast_address

        first_address=net_id.split('.')
        first_address[3]=int(first_address[3])+1
        broadcast_address=net_id.split('.')
        last_address=net_id.split('.')

        for octet in range(len(last_address)):
            last_address[octet]=int(last_address[octet])

        if self.bits_host <= 8:
            octet=3
            metric=1
            count=1
        elif self.bits_host <= 16:
            octet=2
            metric=256
            count=2
        elif self.bits_host <= 24:
            octet=1
            metric=int(256*256)
            count=3
        elif self.bits_host <= 32:
            octet=0
            metric=int(256*256*256)
            count=4

        if last_address[octet] not in range(254,255):
            if self.total_addresses == 256:
                last_address[octet]=int(addr[octet])-1


        div=int(self.total_addresses/metric)


        if count >= 1:

            if octet==3:
                last_address[octet]=last_address[octet]+div-1
            elif octet==2:
                last_address[octet+1]=254
                last_address[octet]=last_address[octet]+div-1
            elif octet==1:
                last_address[octet+2]=254
                last_address[octet+1]=255
                last_address[octet]=last_address[octet]+div-1
            elif octet==0:
                last_address[octet+3]=254
                last_address[octet+2]=255
                last_address[octet+1]=255
                last_address[octet]=last_address[octet]+div-1

        for octet in range(len(first_address)):
            first_address[octet]=str(first_address[octet])

        for octet in range(len(last_address)):
            last_address[octet]=str(last_address[octet])
            broadcast_address[octet]=str(last_address[octet])
            if octet == 3:
                broadcast_address[octet]=str(int(last_address[octet])+1)

        return('.'.join(first_address),\
               '.'.join(last_address),\
               '.'.join(broadcast_address))

    def find_network_id(self,ip,mask):

        net_id=[0,0,0,0]
        addr=ip.split('.')

        for octet in range(len(addr)):
            addr[octet]=int(addr[octet])

        if self.total_hosts <= 1:
            net_id=ip
            return ip

        if self.bits_host <= 8:
            octet=3
            metric=1
            count=1
        elif self.bits_host <= 16:
            octet=2
            metric=256
            count=2
        elif self.bits_host <= 24:
            octet=1
            metric=int(256*256)
            count=3
        elif self.bits_host <= 32:
            octet=0
            metric=int(256*256*256)
            count=4

        if addr[octet] != 0:
            div=int(self.total_addresses/metric)
            while net_id[octet] <= addr[octet]:
                if net_id[octet] <= addr[octet]:
                    net_id[octet]+=div
                else:
                    pass
            net_id[octet]-=div

        for i in range(count):
            addr[octet]=net_id[octet]
            octet+=1


        for octet in range(len(net_id)):
            net_id[octet]=str(net_id[octet])
        for octet in range(len(net_id)):
            addr[octet]=str(addr[octet])

        return('.'.join(addr))

    def find_type(self,ipv4_address):

        addr = ipv4_address.split('.')
        type_string=''
        cidr = int(self.mask_cidr)

        if int(addr[0]) == 10:
            type_string+='Private Address'
            if cidr < 8:
                raise  Exception(f'Unable to assign a {self.mask_cidr}'
                                 f'mask to a Class A Address.')

        elif int(addr[0]) == 172 and int(addr[1]) in range(16,31):
            type_string+='Private Address'
            if cidr < 12:
                raise  Exception(f'Unable to assign a {self.mask_cidr}'
                                 f'mask to a Class B Address.')

        elif int(addr[0]) == 192 and int(addr[1]) == 168:
            type_string+='Private Address'
            if cidr < 16:
                raise  Exception(f'Unable to assign a {self.mask_cidr}'
                                 f' mask to a Class C Address.')

        elif int(addr[0]) == 100 and int(addr[1]) in range(64,127):
            type_string+='Carrier NAT'

        elif int(addr[0]) == 224 and int(addr[1])+int(addr[1]) == 0:
            type_string+='Local Multicast'

        elif int(addr[0]) in range(224,238):
            type_string+='Global Multicast'

        elif int(addr[0]) == 239:
            type_string+='Administrative Multicast'

        elif int(addr[0]) == 127:
            type_string+='Loopback Address'

        elif int(addr[0]) in range(240,255):
            type_string+='Reserved Address'

        elif int(addr[0]) == 198 or int (addr[0]) == 192:
            type_string+='Reserved Address'

        elif int(addr[0]) == 169 and int(addr[1]) == 254:
            type_string+='Link Local Address'

        elif int(addr[0]) == 128:
            type_string+='Public Address'

        elif self.is_broadcast == True:
            type_string+='Limited Broadcast Address'

        elif self.is_ip_mask == True:
            type_string+='Subnet Mask'

        else:
            type_string+='Public Address'

        return type_string

    #def print_all(self):
    def __repr__(self):

        print(  '\nIPv4 Address:'.ljust(30),self.addr,\
                '\nIPv4 Binary:'.ljust(30),self.addr_bin,\
                '\nIPv4 Network ID:'.ljust(30),self.net_id,\
                '\nFirst Address:'.ljust(30),self.first_address,\
                '\nLast Address:'.ljust(30),self.last_address,\
                '\nBroadcast Address:'.ljust(30),self.broadcast_address,\
                '\nMask:'.ljust(30),self.mask_octet,\
                '\nBinary Mask:'.ljust(30),self.mask_bin,\
                '\nCidr Mask:'.ljust(30),self.mask_cidr,\
                '\nHost Bits:'.ljust(30),self.bits_host,\
                '\nTotal Hosts:'.ljust(30),self.total_hosts,\
                '\nTotal Addresses:'.ljust(30),self.total_addresses,\
                '\nAddress Type:'.ljust(30),self.type,\
                '\nPoint to Point:'.ljust(30),self.p2p,\
                #'\nList:'.ljust(30),len(self.address_list),\
                #'\nList:'.ljust(30),self.address_list,\
                '\n')
        return ''

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__,
            sort_keys=True, indent=4)


    @classmethod
    def from_string(cls,empt_str):
        ipv4_address, subnet_mask = empt_str.split('/')
        return cls(ipv4_address, subnet_mask)

    @classmethod
    def from_list(cls,empt_lst):
        ip_data={}
        for c, entry in enumerate(empt_lst,0):
            addr = cls(empt_lst[c])
            #print(entry)
            ip_data[f'ip_address_{c}'] = json.loads(addr.to_json())
            #ip_data.update({f'ip_address_{c}' : json.loads(addr.to_json())})
        return ip_data


def __main__():

    data={}
    if len(sys.argv) > 0:
        for i in range(len(sys.argv)):
            usr_input=sys.argv[i]
            if i == 0:
                 continue
            ipv4 = IPV4(usr_input)
            data.update({f'ip_address_{i-1}' : json.loads(ipv4.to_json())})

    print(json.dumps(data,indent=4))


if __name__=='__main__':
    __main__()
