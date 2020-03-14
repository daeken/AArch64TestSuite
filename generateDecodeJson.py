import json

lines = file('decode.asl').read().split('\n')
insns = []
def parseCase(level, oknowns, fields):
	case = lines.pop(0)
	assert case.startswith('\t' * level + 'case ')
	case = tuple(elem.strip() for elem in case.split('(', 1)[1].split(')', 1)[0].split(','))
	case = () if len(case) == 1 and case[0] == '' else case
	while lines and lines[0].startswith('\t' * (level + 1)):
		line = lines.pop(0).strip()
		assert line.startswith('when (')
		cond = tuple(elem.strip() for elem in line.split('(', 1)[1].split(')', 1)[0].split(','))
		cond = () if len(cond) == 1 and cond[0] == '' else cond
		caused = line.split('=>', 1)[1].strip()
		knowns = oknowns[::]
		for where, what in zip(case, cond):
			if what != '_':
				isNot = what[0] == '!'
				if isNot: what = what[1:]
				assert what[0] == "'" and what[-1] == "'"
				what = what[1:-1]
				if isNot:
					what = 'x' * len(what)
				knowns.append((fields[where] if where in fields else where, what))
		if caused:
			if caused == '__UNALLOCATED' or caused == '__UNPREDICTABLE':
				continue
			assert caused.startswith('__encoding')
			insn = caused.split(' ', 1)[1].strip()
			assert ' ' not in insn
			insns.append((insn, knowns, fields))
		else:
			parseInWhen(level + 2, knowns, fields)

def parseInWhen(level, knowns, fields):
	knowns = knowns[::]
	fields = fields.copy()
	while lines and lines[0].startswith('\t' * level):
		line = lines[0].strip()
		if line.startswith('__field'):
			_, name, value = lines.pop(0).split(' ', 2)
			fields[name] = value
		elif line.startswith('case'):
			parseCase(level, knowns, fields)
		else:
			print 'Unknown line in when body:', `line`
			assert False

def parsePlace(place):
	assert ' +: ' in place
	bottom, size = place.split('+:', 1)
	bottom, size = int(bottom), int(size)
	assert 0 < (bottom + size) <= 32
	return bottom, size

parseCase(0, [], {})

encodings = {}
for insn, knowns, fields in insns:
	encoding = 'x' * 32
	for place, value in knowns:
		bottom, size = parsePlace(place)
		start = 32 - (bottom + size)
		assert size == len(value)
		encoding = encoding[:start] + value + encoding[start + size:]
		assert len(encoding) == 32
	fieldMap = {}
	for i, (name, place) in enumerate(fields.items()):
		bottom, size = parsePlace(place)
		start = 32 - (bottom + size)
		c = chr(ord('a') + i)
		encoding = encoding[:start] + ''.join(c if before == 'x' else before for before in encoding[start:start + size]) + encoding[start + size:]
		if c in encoding:
			fieldMap[c] = name
		assert len(encoding) == 32
	if insn not in encodings:
		encodings[insn] = {}
	encodings[insn][encoding] = fieldMap

json.dump(encodings, file('encodings.json', 'w'), indent=2)
