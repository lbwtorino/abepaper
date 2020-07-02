import charm.core.crypto.cryptobase
from charm.toolbox.pairinggroup import *
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import *
# from charm.toolbox.pairinggroup import PairingGroup, GT
from kpabe import KPABE
from ibe import KPIBE
from full import FULL


def main():

    curve = 'MNT224'
    groupObj = PairingGroup(curve)
    scheme = FULL(groupObj)

    (mpk, msk) = scheme.setup()

    policy = '(123 or 444) and (231 or 999)'	
    sk = scheme.keygen(mpk, msk, policy)

    message = groupObj.random(ZR)
    attri_list = {'123', '842',  '231', '384'}
    # ct = scheme.encrypt(mpk, msk, message, attri_list)
    hash_text = scheme.hash(mpk, msk, message, attri_list)

    p_prime, b, random_r = hash_text['p_prime'], hash_text['b'], hash_text['random_r']
    C, c, epk, sigma = hash_text['C'], hash_text['c'], hash_text['epk'], hash_text['sigma']
    keypair_pk = hash_text['keypair_pk']
    verify_text = scheme.verify(mpk, message, p_prime, b, random_r, C, c, epk, sigma, keypair_pk)
    print(verify_text)

    adapt_text = scheme.adapt(mpk, msk, sk, C, message, p_prime, b, random_r, C, c, epk, sigma, keypair_pk)


    # res = scheme.decrypt(mpk, sk, ct, message)
    # if res == True:
    #     print("Successful Decryption :)")
    # else:
    #     print("Failed Decryption :(")

    # ==========================================
    # curve = 'MNT224'
    # groupObj = PairingGroup(curve)
    # scheme = KPIBE(groupObj)

    # (mpk, msk) = scheme.setup()

    # policy = '(123 or 444) and (231 or 999)'	
    # sk = scheme.keygen(mpk, msk, policy)

    # m = groupObj.random(ZR)
    # attri_list = {'123', '842',  '231', '384'}
    # ct = scheme.encrypt(mpk, msk, m, attri_list)

    # res = scheme.decrypt(mpk, sk, ct, m)
    # if res == True:
    #     print("Successful Decryption :)")
    # else:
    #     print("Failed Decryption :(")
    # ==========================================
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