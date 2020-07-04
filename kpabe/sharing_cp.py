import charm.core.crypto.cryptobase
from charm.toolbox.pairinggroup import *
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import *
from fractions import Fraction
import random

class SHARING(ABEnc):
    def __init__(self, groupObj, verbose = False):
        ABEnc.__init__(self)
        global util, group
        group = groupObj
        util = SecretUtil(group, verbose)
        self.size_A = 5
        self.size_B = 5
        self.threshold = 2

    def compute_polynomial(self, S, a1, a2, x):
        return S + a1 * x + a2 * (x**2)

    def get_GroupA_shares(self, S):
        a1, a2 = group.init(ZR, int(random.randrange(1000))), group.init(ZR, int(random.randrange(1000))), 
        shares = []
        for i in range(self.size_A):
            shares.append(self.compute_polynomial(S, a1, a2, i+1))
        return shares

    def recover_secret(self, shares):
        points = [[2, shares[1]], [4, shares[3]], [5, shares[4]]]
        l_0 = self.compute_l(points[0][0], points[1], points[2])
        l_1 = self.compute_l(points[1][0], points[0], points[2])
        l_2 = self.compute_l(points[2][0], points[0], points[1])
        recovered_polynomial  = []
        for i in range(self.threshold+1):
            constant = Fraction(int(l_0['numerator'][i]) * int(points[0][1]), int(l_0['denominator']))
            x_exp_1 = Fraction(int(l_1['numerator'][i]) * int(points[1][1]), int(l_1['denominator']))
            x_exp_2 = Fraction(int(l_2['numerator'][i]) * int(points[2][1]), int(l_2['denominator']))
            recovered_polynomial.append(int(constant + x_exp_1 + x_exp_2))
        return {'constant':recovered_polynomial[0], 'x_exp_1':recovered_polynomial[1], 'x_exp_2':recovered_polynomial[2]}
            
    def compute_l(self, x_i, point_1, point_2):
        denominator = (x_i - point_1[0]) * (x_i - point_2[0])
        numerator = []
        numerator.append(point_1[0] * point_2[0])
        numerator.append((-point_1[0]) + (-point_2[0]))
        numerator.append(1)
        return {'numerator': numerator, 'denominator':denominator}




