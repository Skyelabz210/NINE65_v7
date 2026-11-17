# Fast RNS division algorithms for fixed divisors with application to RSA encryption
URL: https://web.ece.ucsb.edu/~parhami/pubs_folder/parh94-ipl-rns-div-fixed-divisors.pdf

ELSEVIER

## Information Processing

Letters Information Processing Letters 5 1 ( 1994) 163- 169

## Fast RNS division algorithms for fixed divisors with application to RSA encryption

Ching Yu Hung l, Behrooz Parhami

Department of Electrical and Computer Engineering, University of California, Santa Barbara, Santa Barbara, CA 931069560, USA Communicated by G.R. Andrews; received 8 July 1993; revised 29 April 1994

Keywords: Algorithm complexity; Computer arithmetic; Cryptography; Division; Modular multiplication; Residue number system: Sign detection

1. Introduction

Residue number systems (RNS) present the advantage of fast addition and multiplication over other number systems, and have thus received much attention for high-throughput computations. Digit-parallel, carry-free, and constant-time multiplication and addition is a unique feature of RNS. However, certain op erations such as overflow detection, magnitude comparison, and division are quite difficult in RNS. Thus, RNS is in general limited to ap plications that do not require extensive use of those difficult operations; for example, lilter ing in Digital Signal Processing. By improving RNS division, many application areas for which RNS was previously infeasible, such as RSA encryption, can use the fast RNS multiplication without being penalized too much by the slow RNS division.

* Corresponding author. Email: parhami@ece.ucsb.edu. 
’ Email: ching@simd.ece.ucsb.edu. 

In this paper we consider the problem of divi sion by fixed divisors in RNS. Ordinary integer division is performed; i.e., given the dividend X and the divisor D, we wish to find the quotient Q = LX/D] and th e remainder R = X - QD. The idea is to perform some preprocessing based on the divisor to improve the on-line speed of divisions. Our algorithms do not require inordi nately expensive preprocessing; the cost of pre processing is negligible if 0 (log, D) divisions are performed with the same D, and that is true in the context of RSA encryption. In m-bit encryp tion, up to 2m modular multiplications are per formed with the same m-bit modulus. Several algorithms for general residue division have been proposed in the past [ 1,3,5,8]. Un der the assumption that D is fixed and X is uni formly distributed, the fastest of them [5] has a worst-case time complexity of O(log, X) = O(nb), where n is the number of moduli and b is the number of bits in the largest modulus. In this paper we present two division al gorithms for fixed divisors that achieve time

0020-0190/94/$07.00 @ 1994 Elsevier Science B.V. All rights reserved S.SDI0020-0190(94)00099-K

164 C. Y. Hung, B. Parhami /Information Processing Letters 51 (1994) 163-169 complexity of O(n) for each division. The first algorithm is based on the well-known division method of multiplying by the divisor reciprocal. The second algorithm is based on the Chinese Remainder Theorem (CRT) decoding and ta ble lookup, and requires that the divisor D be relatively prime to all moduli. The second algo rithm requires more storage but is faster. The computation time analysis is based on the usual parallel residue processor assumption: There are n residue processors for an n modulus sys tem, each being capable of one modulus-size modular addition or multiplication in one time step. Additionally, we assume that the divisor D is relatively prime to all moduli, even for the first algorithm that does not require it but becomes somewhat more efficient if it holds. Unless otherwise noted, the computation times given in the paper are parallel times. For soft ware implementation of RNS, we also provide the sequential time complexities. We also present adaptation of both algorithms for RSA encryption. The first algorithm leads to 4n + b time steps per modular multiplica tion, while the second algorithm requires 2n time steps per modular multiplication. The second al gorithm is found to be very competitive with pre viously proposed RSA implementations.

### 2. Basic operations in RNS

2.1. Notation

The expression I,$ denotes the remainder of x divided by y, where x and y are real withy > 0. When x and y are relatively prime integers, with y > 1, the multiplicative inverse of x modulo y, I-y+/& is defined. A residue number system is specified by a list of n pairwise relatively prime moduli, ml,m2,...,mn. A number X is represented in RNS by a list of residues (XI, x2,. . . , xn ), where x1 = IXI,,, . Let it4 = n m, represent the prod uct of all moduli. Let A4, = M/mi and No = Iy’lm,. We also define M[a,b], 1 < a d h d n, as the product of a sequence of moduli: M[a,b] = @_m,. We let M[a,b] = 1 for h < a. Signed numbers in the range -[M/21 < X < 1 (A4 - 1)/2J are represented. These RNS parameters are used throughout the rest of the paper without being explicitly noted in each case. Let b be the number of bits needed to represent each residue. For algorithm efficiency and con venience in analyzing complexities, we assume that the magnitudes of the moduli are more or less uniform. This assumption leads to mi d 2b, Un,fWlj E 1, and M z 2nb. We say a number X is k digits long when X z 2kb.

2.2. Base extension and division by a product of moduli

Let a number X be representable by k residues, k < n, in an n modulus RNS. Base extension refers to the procedure of finding the n - k unknown residues. Base extension is usu ally implemented with mixed-radix conversion (see, e.g., [ 9, pp. 41-471) and takes exactly 2h- - 1 time steps with n residue processors. Base extension can be used to divide a num ber by a product of first powers of moduli [9, pp. 47-501. Let X be the dividend and M[ 1, k] be the divisor. The first k residues of the remain der R = X mod M [ 1, k] are simply the first k residues of X. The n - k remaining residues are found by a base extension from the front k residues toward the back n - k residues, taking 2k - 1 steps. With all residues of the remainder known, the quotient Q can be found by evalu ating (X - R)M [ 1, k ] -’ in one step. However, M[ 1, k]-’ is defined only for the back n - k residues, so only the corresponding residues of Q are known. Another base extension, from the back n - k residues to the front k residues, is applied, taking 2 (n - k) - 1 steps. Totally the division takes 2n - 2 steps.

2.3. Sign detection

In [ 5 1, Hung and Parhami propose a sign es timation procedure that in [log, nj steps indi cates whether a residue number is positive, neg ative, or too small in magnitude to tell. The pro cedure outlined below uses a parameter u, u > 1,

C. Y. Hung, B. Parhami/Information Processing Letters 51 (1994) 163-169 165 to specify input range and output precision: The procedure requires input number X in the range [-( l/2-2-“)M, (l/2-2-“)M]; i.e., a fraction of the dynamic range is excluded. When the out put ES(X) is indeterminate, X is guaranteed to be in the range [ -2-UM, 2-“Ml.

Preprocessing 
1. EF[i][j] = Truncate [jar/mill to the 
(-t)th bit, for 1 < i d n, 0 d j < mi, 
where t = u + [log, nl 
Sign estimation of an input X 

2. EF(X) = Icy__, EF[il [&Ill 
3. ES(X) = +, lfEF(X) < l/2 
4. -, if l/2 < EF(X) < 1 - 2-’ 
5. f, otherwise 

From this sign estimation procedure we con struct a sign detection procedure as follows. The relatively inexpensive sign estimation is tried first. In case it fails (sign being indeterminate), we compute the sign by mixed-radix conver sion. Since the chance of having to use the mixed-radix conversion is low, the sign detec tion requires [log2 n] steps on the average and 2n + [log, n] steps in the worst case (We assume uniform distribution of X in the allowed range, and ignore the time spent on communication.)

2.4. Chinese Remainder Theorem and B (X)

The Chinese Remainder Theorem states that

We define B(X) [9, p. 301 as the number of times the modular summation in Eq. (1) over flows M:

The sign estimation procedure can be adapted to efficiently compute B(X) when input X is nonnegative. The same EF [i] [j] table is used, with parameter u satisfying u > 1. The prepro cessing stage is the same as in sign estimation, followed by:

2. Y = C:=, EF[i][xi] 
3. EF(X) = IYI1, B(X) = Int(Y) 
4. IfEF(X) < l/2 return B(X) 
5. Otherwise, return B(X) = B(X) + 1 

2.5. General division

Reference [ 5 ] also contains an algorithm to perform division in RNS without preprocess ing. We shall call this algorithm general division since it does not require prior knowledge of the divisor. The general division algorithm is based on the well-known binary SRT division. After proper normalization of the dividend X and the divisor D, in each iteration we perform X = 2X, X = 2(X-D),orX = 2(X+D),basedontheesti mated sign of X. To optimize for hardware im plementation, the n operand summation (line 2) of the sign estimation procedure is performed once every [log, n] iterations so that the aver age cost per iteration is constant. The algorithm presented in [5] takes O(log,(M/D) + log, Q) steps, where Q is the quotient computed by the algorithm. The controlled way in which we use general division in our fixed-divisor algorithms renders some of the computations unnecessary. Specifically, when [log, Dl is known or is guar anteed to be within a small range, normalization of D can be simplified. In this case, the general division takes 3[log, Qj time steps on the aver age and 3 [log, Q1 + 2n time steps in the worst case. The extra 2n time is due to a possible final sign detection by mixed-radix conversion. For software implementation, the sequential time is roughly 2n log, Q.

### 3. Multiplying by the divisor reciprocal

Our first algorithm for fixed divisor RNS di vision precomputes the reciprocal of the divisor and uses it to compute the approximate quotient (X is the dividend and D the divisor):

Preprocessing 1. Compute C = [M/Dj, choose k such that 1  2k and that the modular reduction must at least reduce a dividend to half-length to accommodate the squaring in the modular exponentiation. It is necessary, therefore, for the first fixed-divisor algorithm to perform at least b iterations of gen eral division after the coarse modulo stage. The second fixed-divisor algorithm works bet ter. It produces, in the coarse modulo stage, an approximate remainder up to (log, n ) /b + 1 + k digits long. If we make n large enough such that 2[(log,n)/b+ I +k] isnomorethann,weget sufficient reduction in the coarse modulo stage. The second algorithm is also more efficient in this stage, taking 2n steps versus 4n steps for the first algorithm. With the coarse modulo stage of the second algorithm and constant-time multi plication inherent in RNS, each modular multi plication takes about 2n z 4m/b steps. The se quential time is 2n2 NN 8m2/b2 for each modular multiplication.

### 6. Conclusions

We have presented two new algorithms for RNS division with fixed divisors. Adaptation of our second algorithm leads to an efficient RSA implementation, with 4m/b steps per modular multiplication. Existing implementations of RSA encryption can be roughly classified into word-level single processor, bit-level array processors, and word level array processors. Because of the variety of special hardware involved in the designs, it is rather difficult to compare different designs in terms of time complexity; we almost always have to compare actual or estimated encryption rates of the designs. We compare our proposed method with two classical sequential methods: one uses a binary version of multiplying by divisor reciprocal for modular reduction [ 21, the other uses a residue table for modular reduction [6]. With a b-bit processor, a modular multiplication takes 9(m/b)2 and 4(m/b)* steps, respectively.

Treating a b-bit processor as having hardware complexity of b2, the conventional methods have hardware-time products of 9m2 and 4m2. Our method has a hardware complexity of (2m/b)b* = 2mb, and a hardware-time prod uct of 8m2. On the basis of hardware and time complexity, our design competes well with se quential implementation of classical methods. Actual encryption speed depends on the hard ware platform, and is still under investigation. While we have analyzed the time complexity of our algorithms, there are many implemen tation details that must be considered. For ex ample, the communication and storage require ments of the algorithm, integration of the binary residue and residue-binary conversions into the algorithm, and the possibility of systolic imple mentation. Other cryptographic algorithms can benefit from our new techniques. Our choice of RSA to illustrate the efftciency of these tech niques is merely a reflection of the fact that it is better known and more widely applied. We are also looking for other applications of our new residue division algorithms. The EF func tion serves as an index function of residue num bers in our sign detection procedure. In a re cent publication [ 41, Dimauro et al. propose an other index function, called the Sum of Quo tients, for comparison of residue numbers. While a straightforward implementation of their tech nique seems as expensive as residue-to-binary conversion with the Chinese Remainder Theo rem, it remains to be investigated whether a trun cated version leads to an efficient approximate comparison procedure.

Acknowledgement

Careful reading of the manuscript by the ref erees has led to a significant improvement in our presentation. We thank them for their efforts.

### References

[ I] D.K. Banerji, T.-Y. Cheung and V. Ganesan, A high speed division method in residue arithmetic, in: Proc.

C. Y. Hung, B. Parhami /Information Processing Letters 51 (1994) 163-169 169

| 5th Symp. on Computer Arithmetic | (IEEE Press, New [6] S. Kawamura and K. | Hirano, A fast modular |
| --- | --- | --- |
| York, 1981) 158-164. | arithmetic algorithm using | a residue table, in: C.G. |
| [2] P. Barrett, Implementing the | Rivest Shamir and Giinther, ed., Advances in Cryptology, | Proc. Eurocrypt |
| Adleman public key encryption | algorithm on a 88 (Springer, Berlin, 1988) | 245-250. |
| standard digital signal processor, | in: A.M. Odlyzko, [7] C.K. Koc and C.-Y. | Hung, Adaptive m-ary |
| ed., Advances in Cryptology, Proc. Crypt0 86 (Springer, | segmentation and canonical | recoding algorithms for |
| Berlin, 1986) 31 l-323. | multiplication of large binary | numbers, Compuf. |

[3] W.A. Chren Jr, A new residue number system division Math. Appl. 24 (3) (1992) 3-12. 
algorithm, Comput. Math. Appl. 19 (7) ( 1990) 13-29. [8] M. Lu and J.-S. Chiang, A novel division algorithm 
[4] G. Dimauro, S. Impedovo and G. Pirlo, A new for the residue number system, IEEE Trans. Comput. 
technique for fast number comparison in the residue 41 (8) (1992) 1026-1032. 
number system, IEEE Trans. Comput. 42 (5) (1993) [9] N.S. Szabo and R.I. Tanaka, Residue Arithmetic and 
608-612. its Applications to Computer Technology (McGraw- 
[5] C.Y. Hung and B. Parhami, An approximate sign Hill, New York, 1967). 
detection method for residue numbers and its [lo] N. Takagi, A radix-4 modular multiplication hardware 
application to RNS division, Comput. Math. Appl. 27 algorithm for modular exponentiation, IEEE Trans. 
(4) (1994) 23-35. Comput. 41 (8) (1992) 949-956. 

| detection method for residue | numbers and its [lo] N. Takagi, A radix-4 modular | multiplication hardware |
| --- | --- | --- |
| application to RNS division, Comput. | Math. Appl. 27 algorithm for modular exponentiation, | IEEE Trans. |
| (4) (1994) 23-35. | Comput. 41 (8) (1992) 949-956. | |
