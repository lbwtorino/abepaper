import charm.core.crypto.cryptobase
from charm.toolbox.pairinggroup import *
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import *
# from charm.toolbox.pairinggroup import PairingGroup, GT
from kpabe import KPABE
from ibe import KPIBE


def main():

    curve = 'MNT224'
    groupObj = PairingGroup(curve)
    scheme = KPIBE(groupObj)

    (mpk, msk) = scheme.setup()

    policy = '(123 or 444) and (231 or 999)'	
    # policy = '(1 or 3) and (2 or 4)'	
    sk = scheme.keygen(mpk, msk, policy)

    m = groupObj.random(ZR)
    attri_list = {'123', '842',  '231', '384'}
    # attri_list = {'1', '2',  '3'}
    ct = scheme.encrypt(mpk, msk, m, attri_list)

    res = scheme.decrypt(mpk, sk, ct, m)
    print(res)

    # curve = 'MNT224'
    # groupObj = PairingGroup(curve)
    # scheme = KPABE(groupObj)

    # (pp, mk) = scheme.setup()

    # policy = '(123 or 444) and (231 or 999)'	
    # # policy = '(1 or 3) and (2 or 4)'	
    # sk = scheme.keygen(pp, mk, policy)

    # m = groupObj.random(GT)
    # attri_list = {'123', '842',  '231', '384'}
    # # attri_list = {'1', '2',  '3'}
    # ct = scheme.encrypt(pp, m, attri_list)

    # res = scheme.decrypt(pp, sk, ct)

    # if res == m:
    #     fin = "Successful Decryption :)"
    # else:
    #     fin = "Failed Decryption :("
    # print(fin)

if __name__ == "__main__":
    debug = True
    main()