import random, struct

# V0-V31 (16 * 32 bytes)
# X0-X30 (8 * 31 bytes)
# NZCV (1 byte)
# SP (not in input -- always 0x7_ffff_ff00)
# PC (not in input -- always 0x1_0000_0000)

random.seed(0xdeadbeef)

baselines = [
	'\0' * (16 * 32 + 8 * 31) + '\0', 
	'\xFF' * (16 * 32 + 8 * 31) + '\x0F', 
]

for i in xrange(1, 15):
	baselines.append(''.join(chr(random.randrange(256)) for i in xrange(16 * 32 + 8 * 31)) + chr(i))

with file('baselineStates.bin', 'wb') as fp:
	assert len(baselines) <= 0xFF
	fp.write(chr(len(baselines)))
	for baseline in baselines:
		assert len(baseline) == (16 * 32 + 8 * 31 + 1)
		fp.write(baseline)
