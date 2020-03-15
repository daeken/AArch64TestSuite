import json, progressbar, struct
from capstone import *

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

exempt = (
	'brk', 'svc', 'msr', 'mrs', 'sys', 'sysl', 
	'drps', 'dmb', 'dsb', 'esb', 'bti', 
	'clrex', 'csdb', 'hvc', 'isb', 'prfm', 
	'retaa', 'retab', 'sb', 'smc', 'ssbb', 
	'wfe', 'wfi', 'yield', 'hlt', 
)

exemptPrefixes = (
	'ld', 'st', 
	'dcps', 'eret', 
	'aut', 'pac', 'xpac', 
	'psb', 'tsb', 
	'sev', 
	'swp', 
)

filtered = {}
for mnem, insns in progressbar.progressbar(json.load(file('testInsns.json')).items()):
	if mnem in exempt or any(mnem.startswith(prefix) for prefix in exemptPrefixes):
		continue
	for insn in insns:
		code = struct.pack('<I', insn)
		mnem = list(md.disasm(code, 0x100000000))[0].mnemonic
		if mnem in exempt or any(mnem.startswith(prefix) for prefix in exemptPrefixes):
			continue
		if mnem not in filtered:
			filtered[mnem] = []
		filtered[mnem].append(insn)
json.dump(filtered, file('filteredInsns.json', 'w'), indent=2)

# 10782001 total instructions
