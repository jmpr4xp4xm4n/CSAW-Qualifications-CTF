from pwn import *
import re
d = re.compile(r"\d+")

def SmartAttack(P,Q,p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P,y_P = p_times_P.xy()
    x_Q,y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)


host = "crypto.chal.csaw.io"
port = 5002

r = remote(host,port)
print(r.recvuntil(b"p = "))
p = int(r.recvuntil(b"\n").decode().strip()) 
print(r.recvuntil(b"a = "))
a = int(r.recvuntil(b"\n").decode().strip()) 
print(r.recvuntil(b"b = "))
b = int(r.recvuntil(b"\n").decode().strip()) 
print(r.recvuntil(b"P1: "))
Gx,Gy,_ = d.findall(r.recvuntil(b"\n").decode())
Gx = int(Gx)
Gy = int(Gy)
print(r.recvuntil(b"P2: "))
Px,Py,_ = d.findall(r.recvuntil(b"\n").decode())
Px = int(Px)
Py = int(Py)

E = EllipticCurve(GF(p),[a,b])
G = E(Gx,Gy)
P = E(Px,Py)
print(r.recvuntil(b"?:"))
secret  = SmartAttack(G,P,p)
r.sendline(str(secret).encode())
print(r.recvuntil(b"\n"))
print(r.recvuntil(b"\n"))
print(r.recvuntil(b"\n"))
print(r.recvuntil(b"p = "))
p = int(r.recvuntil(b"\n").decode().strip()) 
print(r.recvuntil(b"a = "))
a = int(r.recvuntil(b"\n").decode().strip()) 
print(r.recvuntil(b"b = "))
b = int(r.recvuntil(b"\n").decode().strip()) 
print(r.recvuntil(b"P1: "))
Gx,Gy,_ = d.findall(r.recvuntil(b"\n").decode())
Gx = int(Gx)
Gy = int(Gy)
print(r.recvuntil(b"P2: "))
Px,Py,_ = d.findall(r.recvuntil(b"\n").decode())
Px = int(Px)
Py = int(Py)
E = EllipticCurve(GF(p), [a,b])
G = E(Gx,Gy)
P = E(Px,Py)
k = 1
while True :
    if (p**k - 1 ) % E.order() == 0 :
        break
    k+=1
Ed = EllipticCurve(GF(p**k),[a,b])
G_ = Ed(G)
P_ = Ed(P)
R = Ed.random_point()
m = R.order()
w = gcd(m, G.order())
Q = (m//w)*R
n = G.order()
alpha = G_.weil_pairing(Q,n)
beta = P_.weil_pairing(Q,n)
dlog = beta.log(alpha)
print(r.recvuntil(b"?:"))
r.sendline(str(dlog).encode())
print(r.recvuntil(b"\n"))
print(r.recvuntil(b"\n"))
print(r.recvuntil(b"\n"))
print(r.recvuntil(b"p = "))
p = int(r.recvuntil(b"\n").decode().strip()) 
print(r.recvuntil(b"a = "))
print(r.recvuntil(b"\n"))
print(r.recvuntil(b"b = "))
print(r.recvuntil(b"\n"))
print(r.recvuntil(b"\n"))
print(r.recvuntil(b"P1: "))
gx,gy = d.findall(r.recvuntil(b"\n").decode())
gx = int(gx)
gy = int(gy)
print(r.recvuntil(b"P2: "))
px,py = d.findall(r.recvuntil(b"\n").decode())
px = int(px)
py = int(py)
F = GF(p)
M = Matrix(F, [[gx,1],[px,1]])
a,b = M.solve_right(vector([gy^2-gx^3,py^2-px^3]))
K.<x> = F[]
f = x^3 + a*x + b
roots = f.roots()
if roots[0][1] == 1:
    beta, alpha = roots[0][0], roots[1][0]
else:
    alpha, beta = roots[0][0], roots[1][0]

slope = (alpha - beta).sqrt()
u = (gy + slope*(gx-alpha))/(gy - slope*(gx-alpha))
v = (py + slope*(px-alpha))/(py - slope*(px-alpha))

secret = discrete_log(v, u)
print(r.recvuntil(b"?:"))
r.sendline(str(secret).encode())
print(r.recvuntil(b"\n"))
print(r.recvuntil(b"\n"))
print(r.recvuntil(b"\n"))
print(r.recvuntil(b"\n"))
print(r.recvuntil(b"\n"))
#flag{4Ll_0f_tH353_4tT4cK5_R3lY_0N_51mPl1FY1n9_th3_D15cr3t3_l09_pr08l3m}
