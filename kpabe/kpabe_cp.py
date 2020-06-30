from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from msp import MSP


class BP20ABE(ABEnc):
    def __init__(self, group_obj, assump_size, verbose=False):
        ABEnc.__init__(self)
        self.group = group_obj
        self.assump_size = assump_size  # size of linear assumption, at least 2
        self.util = MSP(self.group, verbose)

    def setup(self):
        """
        Generates public key and master secret key.
        """
        # genrate random terms g, u, h, w
        g_u_h_w = []
        for i in range(4):
            g_u_h_w.append(self.group.random(G1))

        # genrate random alpha
        alpha = self.group.random(ZR)

        # compute paring e(g,g)^alpha
        e_gg_alpha = pair(g, g) ** alpha

        # the public key
        pk = {'g': g_u_h_w[0], 'u': g_u_h_w[1], 'h': g_u_h_w[2], 'w': g_u_h_w[3],'e_gg_alpha': e_gg_alpha}

        # the master secret key
        msk = {'alpha': alpha}

        return pk, msk

    def keygen(self, pk, msk, policy_str)
        """
        Generate a key for policy.
        """
        # Convert a Boolean formula represented as a string into a policy represented like a tree.
        policy = self.util.createPolicy(policy_str)
        # Convert a policy into a monotone span program (MSP) represented by a dictionary with (attribute, row) pairs
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        # num_cols is n
        num_cols = self.util.len_longest_row

        # compute vector y
        y = []
        y.append(msk['alpha'])
        for i in range(num_cols - 1):
            y.append(self.group.random(ZR))

        # compute share of vector lambda
        share_lambda = []
        # Rho(i) for later use
        Rho = []
        for attr, row in mono_span_prog.items():
            tmp = 0
            for i in range(len(row)):
                tmp += row[i] * y[i]
            share_lambda.append(tmp)
            Rho.append(self.util.strip_index(attr))

        # compute value of l
        l = len(share_lambda)

        # genrate random t_1, t_2.......t_l
        t = []
        for i in range(l):
            t.append(self.group.random(ZR))
        
        # compute K
        K = {}
        g = pk['g']
        w = pk['w']
        u = pk['u']
        h = pk['h']
        for i in range(l):
            tmp = []
            tmp.append((g ** share_lambda[i]) * (w ** t[i]))
            tmp.append((h * u ** (Rho[i])) ** (-t[i]))
            tmp.append(g ** t[i])
            K[i] =  tmp
        
        return {'policy': policy, 'K': K}

    def encrypt(self, pk, msk, msg, attr_list):
        """
        Encrypt a message msg under a attribute string.
        """
        # compute k
        k = len(attr_list)
        
        # generate k+1 random terms
        r = []
        # generate s
        r.append(self.group.random(ZR))
        for i in range(k):
            r.append(self.group.random(ZR))

        alpha = msk['alpha']
        g = pk['g']
        w = pk['w']
        u = pk['u']
        h = pk['h']
        # compute C, C_0
        C = m * (pair(g, g) ** (alpha * s))
        C_0 = g ** s

        # compute dict C_t
        C_t = {}
        for i in range(k):
            tmp = []
            tmp.append(g ** r[i+1])
            tmp.append((h * u ** attr_list[i]) * (w ** (-s)))
            C_t[i] = tmp
        
        # the ciphertext
        return {'attr_list': attr_list, 'C': C, 'C_0': C_0, 'C_t': C_t}
    
    def decrypt(self, pk, msk, ctxt, key):
        """
        Decrypt ciphertext ctxt with key.
        """
        # Determine whether a given set of attributes satisfies the policy 
        # (returns false if it doesn’t).
        nodes = self.util.prune(key['policy'], ctxt['attr_list'])
        if not nodes:
            print ("Policy not satisfied.")
            return None
        
        mono_span_prog = self.util.convert_policy_to_msp(key['policy'])
        num_cols = self.util.len_longest_row

        B = 1
        for node in nodes:
            attr_stripped = self.util.strip_index(node.getAttributeAndIndex())
            i = 0
            pair_value = 1 
            for attr, row in mono_span_prog.items():
                if attr != attr_stripped:
                    i += 1
                index_t = ctxt['attr_list'].index(attr)
                pair_value *= pair(ctxt['C_0'], key['K'][i][0])
                pair_value *= pair(ctxt['C_t'][index_t][0], key['K'][i][1])
                pair_value *= pair(ctxt['C_t'][index_t][1], key['K'][i][2])
                # w_i missing
            B *= pair_value
        
        return ctxt['C'] / B