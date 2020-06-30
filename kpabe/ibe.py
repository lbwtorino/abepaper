import charm.core.crypto.cryptobase
from charm.toolbox.pairinggroup import *
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import *

class KPIBE(ABEnc):
    def __init__(self, groupObj, verbose = False):
        ABEnc.__init__(self)
        global util, group
        group = groupObj
        util = SecretUtil(group, verbose)
        self.k = 10
        self.index_i = 5
        self.index_j = 5

    def setup(self):
        # g, u, h, w, e(g, g)^alpha
        # G2 --> H, G1 --> G
        h = group.random(G2)
        g, u, v, w = group.random(G1), group.random(G1), group.random(G1), group.random(G1)
        egg = pair(g,h)**alpha
        # alpha, beta, theta, 
        alpha = group.random(ZR)
        beta = group.random(ZR)
        theta = group.random(ZR)
        # z_1,z_2......z_k, {g_1, g_2,....g_k}, and {h_1, h_2,....h_k}
        # {g1^alpha, g2^alpha,...gk^alpha}, and {h1^alpha, h2^alpha,...hk^alpha}
        z = []
        vector_g, vector_h, vector_g_alpha, vector_h_alpha = [], [], [], []
        for i in range(self.k):
            z.append(group.random(ZR))
            vector_g.append(g**z)
            vector_h.append(h**z)
            vector_g_alpha.append(vector_g[i]**alpha)
            vector_h_alpha.append(vector_h[i]**alpha)
        # g^beta, h^1/alpha, h^beta/alpha, egg^theta/alpha
        g_beta =  g**beta 
        h_1_alpha = h**(1/alpha)
        h_beta_alpha =  h**(beta/alpha)
        egg_theta_alpha = egg**(theta/alpha)

        # mpk
        mpk = {'g':g, 'u':u, 'v':v, 'w':w, 'h':h, 'egg':egg, 'vector_g_alpha': vector_g_alpha, 'vector_h_alpha': vector_h_alpha, 'g_beta': g_beta, 'h_1_alpha': h_1_alpha, 'h_beta_alpha': h_beta_alpha, 'egg_theta_alpha': egg_theta_alpha}
        # msk
        msk = {'alpha':alpha, 'beta':beta, 'theta': theta}
        return (mpk, msk)



    def keygen(self, mpk, msk, policy_str):
        # the secret alpha will be shared according to the policy	
        policy = util.createPolicy(policy_str)
        # retrieve the attributes that occur in a policy tree in order (left to right)
        a_list = util.getAttributeList(policy)
        # compute vector lambda
        shares = util.calculateSharesDict(msk['alpha'], policy)
        # compute K{}, [t_1,t_2,....t_n], [r_1,r_2, .....r_n] 
        SK1, SK2, SK3 = {}, {}, {}
        t = []
        r = []
        for i in a_list:
            t_i = group.random(ZR)
            r_i = group.random(ZR)
            # remove index, only return attribute name
            inti = int(util.strip_index(i)) #NOTICE THE CONVERSION FROM STRING TO INT
            # compute K_(Tau,0)
            SK1[i] = mpk['g']**shares[i] * mpk['w']**t_i
            # compute K_(Tau,1)
            rho_i = group.init(ZR, inti)
            SK2[i] = (mpk['u']**rho_i * mpk['v'])**(-t_i)
            # compute K_(Tau,2)
            SK3[i] = mpk['h']**t_i
            t.append(t_i)
            r.append(r_i)
        
        # sk_0
        sk_0 = {}
        sum_t, sum_r = sum(t), sum(r)
        g_t_alpha = mpk['g']**(sum_t/msk['alpha'])
        g_r = mpk['g']**sum_r
        sk_0['g_t_alpha'] = g_t_alpha
        sk_0['g_r'] = g_r
        # sk_1
        I = []
        vector_i = 1
        for i in range(self.index_i):
            tmp = group.random(ZR)
            vector_i *= mpk['vector_g_alpha'][self.k-1-i]**tmp
            I.append(tmp)
        vector_i *= mpk['g']
        sk_1 = mpk['g']**msk['theta'] * vector_i**sum_t * mpk['g']**(msk['beta']*sum_r)

        return {'Policy':policy_str, 'SK1':SK1, 'SK2':SK2, 'SK3':SK3, 'sk_0': sk_0, 'sk_1': sk_1}



    def encrypt(self, mpk, message, attri_list):
        s = group.random(ZR)	
        wS = mpk['w']**(-s)
        h, alpha, beta = mpk['h'], msk['alpha'], msk['beta']
        # compute C{}
        CT1, CT2 = {}, {}
        r = []
        for i in attri_list:
            tmp = group.random(ZR)
            # compute C_(Tau,0)
            CT1[i] = mpk['h']**tmp
            # compute C_(Tau,1)
            A_T = group.init(ZR, int(i))
            CT2[i] = (mpk['u']**A_T * mpk['v'])**tmp * wS

        # ct
        input_for_hash = str(mpk['egg']**s) + str(pair(mpk['g'],mpk['h'])**(msk['theta'] * s / msk['alpha']))
        hashed_value = group.hash(input_for_hash, ZR)
        _ct = int(R) ^ int(hashed_value)
        ct = group.init(ZR, _ct)
        # ct_0
        ct_0 ={}
        ct_0['h_s'] = h**s
        ct_0['h_s_alpha'] = h**(s/alpha)
        ct_0['h_beta_s_alpha'] = h**(beta*s/alpha)
        # ct_1
        I = []
        vector_j = 1
        for j in range(self.index_j):
            tmp = group.random(ZR)
            vector_j *= mpk['vector_h_alpha'][self.k-1-i]**tmp
            I.append(tmp)
        vector_j *= mpk['h']

        #NOTICE THE CONVERSION FROM STRING TO INT
        #Have to be an array for util.prune
        # attri_list = [i for i in attri_list] 
        return { 'attri_list':attri_list, 'ct':ct, 'CT1':CT1, 'CT2':CT2, 'ct_0':ct_0, 'ct_1':ct_1} 

    def decrypt(self, mpk, sk, ct):
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
            # compute Tau, which is the index of attribute Gamma(i) in attri_list
            Tau = pruned_list[j].getAttribute( ) #without the underscore
            # compute i, I={i: rho(i) in attri_list}
            i = pruned_list[j].getAttributeAndIndex( ) #with the underscore
            # compute B
            B *= (pair(sk['SK1'][i], ct['CT1'][0]) * pair(sk['SK2'][i], ct['CT1'][i]) * pair(ct['CT2'][i], sk['SK3'][i])) ** w[i]
    
        # A
        numerator = pair(sk['sk_1'], ct['CT2'][0])
        denominator = pair(sk['SK1'][0], ct['ct_1']) * pair(sk['SK2'][0], ct['ct_1'])

        # return ct['C'] / B 