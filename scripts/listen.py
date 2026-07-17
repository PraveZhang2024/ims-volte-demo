import requests, json, os, sys, argparse


def find_data(msisdn_or_imsi: str) -> dict:
    servers = ['10.2.30.190', '10.2.30.90']
    res = {
        'msisdn': '', 'imsi': '', 'ims_ip': '', 'k': '', 'opc': '', 'realm': ''
    }
    for server in servers:
        if len(msisdn_or_imsi) == 15:
            eps = requests.get(f'http://{server}:8403/v2.0/epsSubscription/subscriber/{msisdn_or_imsi}').json()
            if 'subscriber' not in eps:
                continue
            eps = eps['subscriber']
        else:
            eps = requests.get(f'http://{server}:8403/v2.0/epsSubscription/subscriber?msisdnPrefix={msisdn_or_imsi}').json()
            if 'subsDataList' not in eps or not len(eps['subsDataList']) == 1:
                continue
            eps = eps['subsDataList'][0]
        res['msisdn'] = eps['msisdn']
        res['imsi'] = eps['imsi']
        ip_split = list(map(int, server.split('.')))
        ip_split[-1] -= 30  # 190 → 160，90 → 60
        res['ims_ip'] = '.'.join(map(str, ip_split))
        auc = requests.get(f'http://{server}:8403/v2.0/authentication/user/{res["imsi"]}', timeout=2).json().get('user')
        res['k'], res['opc'] = auc['ki'], auc['opc']
        realm = 'ims.mnc0{}.mcc{}.3gppnetwork.org'.format(res['imsi'][3:5], res['imsi'][:3])
        res['realm'] = realm
        return res
    return None


def main():
    msisdn_or_imsi = sys.argv[1]
    data = find_data(msisdn_or_imsi)
    if not data:
        print('未找到 {} 的信息'.format(msisdn_or_imsi))
        return -1
    print('listen = {}'.format(data))
    os.system('bash -lc \'source /root/venv/bin/activate && cd /root/ims-volte-demo && python3 main.py --config config/demo.yaml --mode listen  --log-level DEBUG --pcscf-ip  {}  --pcscf-port 5060 --imsi {} --impi {} --impu "{}"  --realm {} --k {} --opc {} \''.format(
        data['ims_ip'],
        data['imsi'],
        '{}@{}'.format(data['imsi'], data['realm']),
        'sip:+{}@{}'.format(data['msisdn'], data['realm']),
        data['realm'],
        data['k'],
        data['opc'],
    ))
    return 0


if __name__ == '__main__':
    sys.exit(main())
