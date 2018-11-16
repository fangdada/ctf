quote from: https://r2s4x.github.io/writeup/2017/03/20/0ctf-2017-enginetest-writeup.html

solve
========

```python


from z3 import *
from struct import unpack_from


def solve(records):
    B = []
    N = 34857
    for i in xrange(N):
        B.append(BitVec(i, 1))

    s = Solver()
    #for i in B:
    #    s.add(Or(i == 0, i == 1))

    s.add(B[0] == 0)
    s.add(B[1] == 1)
    s.add(B[34792] == 1)

    for i in xrange(34):
        s.add(B[2 + i * 8 + 7] == 0)

    for i in xrange(len(records)):
        op_type, q1, q2, q3, q4 = records[i]
        if op_type == 1:
            s.add(B[q1] & B[q2] == B[q4])
        elif op_type == 2:
            s.add(B[q1] | B[q2] == B[q4])
        elif op_type == 3:
            s.add(B[q1] ^ B[q2] == B[q4])
        elif op_type == 4:
            s.add(Or(And(B[q1] == 1, B[q2] == B[q4]), And(B[q1] == 0, B[q3] == B[q4])))

    r = []
    if s.check() == sat:
        model = s.model()
        for i in xrange(N):
            r.append(model[B[i]].as_long())
    else:
        print 'Oops'

    return r


def get_records():
    with open('cp', 'rb') as f:
        cp = f.read()

    some_val, count = unpack_from('<QQ', cp)

    res = []
    for i in xrange(count):
        res.append(unpack_from('<QQQQQ', cp, i * 40 + 16))

    return res


def set_bit(n, b, p):
    return n | (b << p)


def get_str(r, offset, lenght):
    s = ''
    n = 0
    l = r[offset:]
    for i in xrange(lenght * 8):
        n = set_bit(n, l[i], i & 7)
        if i > 0 and i & 7 == 7:
            s += chr(n)
            n = 0
    return s

records = get_records()

print 'Wait'
l = solve(records)
print 'Done'

print get_str(l, 2, 34)
print get_str(l, 34793, 8)


```
