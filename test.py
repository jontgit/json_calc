import ipv4, mac, json

def get_input():

    ipaddr=[]
    macaddr=[]
    hosts={}

    while True:
        try:
            dev_count = int(input('How many devices:  '))
        except:
            print('Please enter an integer.')
            continue
        break

    for dev in range(int(dev_count)):

        host_name = input(f'Device name:  ')
        while True:
            try:
                inter_count = int(input(f'Device {dev} - how many ints:  '))
            except:
                print('Please enter an integer.')
                continue
            break


        hosts_t={host_name:{'int_count':inter_count}}
        hosts.update(hosts_t)

        for i in range(int(inter_count)):
            while True:
                try:
                    ipaddr.append(input(f'Device {dev+1}, Interface {i+1} IP:  '))
                    macaddr.append(input(f'Dev {dev+1}, Interface {i+1} MAC:  '))
                except:
                    print('Invalid input.')
                    continue
                break

    json_data(ipaddr,macaddr,hosts)

def json_data(ip_add,mac_add,hosts):

    data={}
    ints={}
    data_ints={}

    x = 0
    c = 0

    ip = ipv4.IPV4.from_list(ip_add)
    mac_ = mac.MAC.from_list(mac_add)

    print(hosts)

    for host in hosts:
        int_quantity = int(hosts[host]['int_count'])
        data_ints['hostname']=host
        data_ints['interface_count']=hosts[host]['int_count']
        for i in range (int_quantity):
            ints['ip'] = ip[f'ip_address_{x}']
            ints['mac'] = mac_[f'mac_address_{x}']
            data_ints[f'int_{i}']=ints
            ints={}
            data[c]=data_ints
            x+=1
        c+=1
        data_ints={}

    with open('./test.json', 'w') as json_file:
        json.dump(data,json_file)

get_input()
