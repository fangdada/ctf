import re
def str_to_equation(string):
	res = []
	for x in xrange(2, 20):
		f = "%1\\$\\*" + str(x) + "\\$s"
		res.append(len([m.start() for m in re.finditer(f, string)]))
	return res

def get_all_formats():
	res = []
	for addr in XrefsTo(0x400590, flags=0):
		mov_esi = addr.frm - 12
		assert GetMnem(mov_esi) == "mov" and "esi" in GetOpnd(mov_esi, 0)
		res.append(GetString(GetOperandValue(mov_esi, 1)))
	return res

def get_equations():
	equations = []
	formats = get_all_formats()
	for s in formats:
		equations.append(str_to_equation(s))
	return equations

def get_results():
	res = []
	p = 0x627100
	for i in xrange(0, 18):
		res.append(Dword(p + 4 * i))
	return res
