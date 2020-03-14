import json, progressbar, struct
from capstone import *

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

for insns in progressbar.progressbar(json.load(file('testInsns.json')).values()):
	for insn in insns:
		code = struct.pack('<I', insn)
		x = list(md.disasm(code, 0x100000000))[0]
		print x.mnemonic, x.op_str
