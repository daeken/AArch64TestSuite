import json, struct
import progressbar
from capstone import *

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

stripe0 = 0b01010101010101010101010101010101
stripe1 = 0b10101010101010101010101010101010

def testPattern(size, name):
	ones = (1 << size) - 1
	patterns = set((0, ones))

	for i in xrange(size):
		patterns.add(1 << i)
		patterns.add(ones ^ (1 << i))

	patterns.add(stripe0 & ones)
	patterns.add(stripe1 & ones)

	return list(patterns)

def generatePermutations(patterns):
	if len(patterns) == 1:
		for i in patterns:
			yield i
	elif len(patterns) == 2:
		a, b = patterns
		for i in a:
			for j in b:
				yield [i, j]
	else:
		a = patterns[0]
		for j in generatePermutations(patterns[1:]):
			for i in a:
				yield [i] + j

def generateTestInsns(bits, cToName):
	if len(cToName) == 0:
		return None, None
	nameToC = {name : c for c, name in cToName.items()}
	fieldSizes = {name : len([1 for b in bits if b == c]) for c, name in cToName.items()}
	patterns = [testPattern(size, name) for name, size in fieldSizes.items()]
	base = int(''.join('0' if b not in '01' else b for b in bits), 2)
	fieldOffsets = [31 - bits.rfind(nameToC[name]) for name in fieldSizes.keys()]
	insns = []
	mnem = None
	for permutation in generatePermutations(patterns):
		insn = base
		for offset, value in zip(fieldOffsets, permutation):
			insn |= value << offset
		code = struct.pack('<I', insn)
		try:
			tmnem = list(md.disasm(code, 0x100000000))[0].mnemonic
		except:
			continue
		if mnem is None:
			mnem = tmnem
		insns.append(insn)
	return mnem, insns

allEncodings = json.load(file('encodings.json'))
allTests = {}
for insn, encodings in progressbar.progressbar(allEncodings.items()):
	for bits, fieldMap in encodings.items():
		mnem, insns = generateTestInsns(bits, fieldMap)
		if mnem is None:
			continue
		if mnem not in allTests:
			allTests[mnem] = []
		allTests[mnem] += insns

json.dump(allTests, file('testInsns.json', 'w'), indent=2)
