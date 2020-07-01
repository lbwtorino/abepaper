import charm.core.crypto.cryptobase
from charm.toolbox.pairinggroup import *
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import *

class KPABE(ABEnc):
    def __init__(self, groupObj, verbose = False):
        ABEnc.__init__(self)
        global util, group
        group = groupObj
        util = SecretUtil(group, verbose)

    def setup(self):
        # compute g, u, h, w
        g = group.random(G2)
        g2, u, h, w = group.random(G1), group.random(G1), group.random(G1), group.random(G1)
        # compute alpha --> msk
        alpha = group.random(ZR)
        # compute e(g, g)^alpha
        egg = pair(g2,g)**alpha
        # public key
        pp = {'g':g, 'g2':g2, 'u':u, 'h':h, 'w':w, 'egg':egg}
        # msk
        mk = {'alpha':alpha}
        return (pp, mk)



    def keygen(self, pp, mk, policy_str):
        # the secret alpha will be shared according to the policy	
        policy = util.createPolicy(policy_str)
        # retrieve the attributes that occur in a policy tree in order (left to right)
        a_list = util.getAttributeList(policy)
        # compute vector lambda
        shares = util.calculateSharesDict(mk['alpha'], policy)
        # compute K{}
        K0, K1, K2 = {}, {}, {}
        for i in a_list:
            # remove index, only return attribute name
            inti = int(util.strip_index(i)) #NOTICE THE CONVERSION FROM STRING TO INT
            print(type(inti))
            ri = group.random(ZR)
            # compute K_(Tau,0)
            K0[i] = pp['g2']**shares[i] * pp['w']**ri
            # compute K_(Tau,1)
            rho_i = group.init(ZR, inti)
            print(rho_i)
            K1[i] = (pp['u']**rho_i * pp['h'])**(-ri)
            # compute K_(Tau,2)
            K2[i] = pp['g']**ri
        return {'Policy':policy_str, 'K0':K0, 'K1':K1, 'K2':K2}



    def encrypt(self, pp, message, attri_list):
        # S is a list of attributes written as STRINGS i.e. {'1', '2', '3',...}
        s = group.random(ZR)	
        C = message * (pp['egg']**s)
        C0 = pp['g']**s
        wS = pp['w']**(-s)
        # compute C{}
        C1, C2 = {}, {}
        for i in attri_list:
            r_Tau = group.random()
            # compute C_(Tau,0)
            C1[i] = pp['g']**r_Tau
            # compute C_(Tau,1)
            A_T = group.init(ZR, int(i))
            C2[i] = (pp['u']**A_T * pp['h'])**r_Tau * wS

        #NOTICE THE CONVERSION FROM STRING TO INT
        #Have to be an array for util.prune
        # attri_list = [i for i in attri_list] 
        return { 'attri_list':attri_list, 'C':C, 'C0':C0, 'C1':C1, 'C2':C2 } 

    def decrypt(self, pp, sk, ct):
        # Convert a Boolean formula represented as a string into a policy represented like a tree
        policy = util.createPolicy(sk['Policy'])
        # compute w_i
        # Given a policy, returns a coefficient for every attribute
        w = util.getCoefficients(policy)
        # determine whether a given set of attributes satisfies the policy
        pruned_list = util.prune(policy, ct['attri_list'])
        if (pruned_list == False):
            return group.init(GT,1)
        # B = group.init(GT,1) # the identity element of GT
        # compute B
        B = 1
        for j in range(0, len(pruned_list)):
            # compute Tau, which is the index of attribute rho(i) in attri_list
            Tau = pruned_list[j].getAttribute( ) #without the underscore
            # compute i, I={i: rho(i) in attri_list}
            i = pruned_list[j].getAttributeAndIndex( ) #with the underscore
            # compute B
            B *= ( pair(ct['C0'], sk['K0'][i]) * pair(ct['C1'][Tau], sk['K1'][i]) * pair(ct['C2'][Tau], sk['K2'][i] ) ) ** w[i]
        return ct['C'] / B 