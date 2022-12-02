import z3



val = z3.StringVal( "1234567890" )
print(z3.Extract(z3.StringVal("abcd"),2,1).sort())
print(z3.simplify(z3.Extract(z3.StringVal("abcd"),2,1)))
