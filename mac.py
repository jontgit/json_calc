import sys, re, json, platform, subprocess, os, csv
from itertools import islice


if platform.system().lower()=='windows':
    os.chdir(os.getcwd())
    directory = os.getcwd()
    slash = '\\'

else:
    os.chdir(os.path.dirname(sys.argv[0]))
    directory = Path().absolute()
    slash = '/'

oui_table = str(str(directory)+slash+'oui.txt')

class MAC:

    def __init__(self, input_string):
        mac_and_oui = self.format_input(input_string)
        self.addr = mac_and_oui[0]
        self.oui = mac_and_oui[1]
        self.vendor = self.oui_lookup()


    def format_input(self, mac):

        if re.search('-', mac):
            mac = mac.replace('-','')
        elif re.search('.', mac):
            mac = mac.replace('.','')
        elif re.search(':', mac):
            mac = mac.replace(':','')

        if len(mac) != 12:
            raise Exception(f'Invalid Mac address: {mac}')

        oui = mac[:6].upper()
        mac = ':'.join(a+b for a,b in zip(mac[::2], mac[1::2])).upper()

        return mac, oui

    def oui_lookup(self):
        with open(oui_table,'r') as ouireader:

            count = len(list(csv.reader(open(oui_table))))
            while True:
                next_n_lines = list(islice(ouireader, 100))
                for line in next_n_lines:

                    if re.search(str(self.oui),str(line)):
                        vendor = line.split(' ',1)
                        vendor = str(vendor[1].replace('\n',''))
                        return vendor

                if not next_n_lines:
                    break

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__,
            sort_keys=True, indent=4)

    @classmethod
    def from_string(cls,empt_str):
        pass

    @classmethod
    def from_list(cls,empt_lst):
        data={}
        for c, entry in enumerate(empt_lst,0):
            addr = cls(empt_lst[c])
            data.update({f'mac_address_{c}' : json.loads(addr.to_json())})
        return data

def __main__():
    m = MAC('18-35-d1-69-05-38')
    print(m.oui)
    print(m.vendor)

if __name__=='__main__':
    __main__()
