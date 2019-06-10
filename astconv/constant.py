Precedence = {
    "Sequence": 0,
    "Yield": 1,
    "Await": 1,
    "Assignment": 1,
    "Conditional": 2,
    "ArrowFunction": 2,
    "LogicalOR": 3,
    "LogicalAND": 4,
    "BitwiseOR": 5,
    "BitwiseXOR": 6,
    "BitwiseAND": 7,
    "Equality": 8,
    "Relational": 9,
    "BitwiseSHIFT": 10,
    "Additive": 11,
    "Multiplicative": 12,
    "Unary": 13,
    "Postfix": 14,
    "Call": 15,
    "New": 16,
    "TaggedTemplate": 17,
    "Member": 18,
    "Primary": 19
}

BinaryPrecedence = {
    '||': Precedence["LogicalOR"],
    '&&': Precedence["LogicalAND"],
    '|': Precedence["BitwiseOR"],
    '^': Precedence["BitwiseXOR"],
    '&': Precedence["BitwiseAND"],
    '==': Precedence["Equality"],
    '!=': Precedence["Equality"],
    '===': Precedence["Equality"],
    '!==': Precedence["Equality"],
    'is': Precedence["Equality"],
    'isnt': Precedence["Equality"],
    '<': Precedence["Relational"],
    '>': Precedence["Relational"],
    '<=': Precedence["Relational"],
    '>=': Precedence["Relational"],
    'in': Precedence["Relational"],
    'instanceof': Precedence["Relational"],
    '<<': Precedence["BitwiseSHIFT"],
    '>>': Precedence["BitwiseSHIFT"],
    '>>>': Precedence["BitwiseSHIFT"],
    '+': Precedence["Additive"],
    '-': Precedence["Additive"],
    '*': Precedence["Multiplicative"],
    '%': Precedence["Multiplicative"],
    '/': Precedence["Multiplicative"]
}

F_ALLOW_IN = 1
F_ALLOW_CALL = 1 << 1
F_ALLOW_UNPARATH_NEW = 1 << 2
F_FUNC_BODY = 1 << 3
F_DIRECTIVE_CTX = 1 << 4
F_SEMICOLON_OPT = 1 << 5

E_FTT = F_ALLOW_CALL | F_ALLOW_UNPARATH_NEW
E_TTF = F_ALLOW_IN | F_ALLOW_CALL
E_TTT = F_ALLOW_IN | F_ALLOW_CALL | F_ALLOW_UNPARATH_NEW
E_TFF = F_ALLOW_IN
E_FFT = F_ALLOW_UNPARATH_NEW
E_TFT = F_ALLOW_IN | F_ALLOW_UNPARATH_NEW

S_TFFF = F_ALLOW_IN
S_TFFT = F_ALLOW_IN | F_SEMICOLON_OPT
S_FFFF = 0x00
S_TFTF = F_ALLOW_IN | F_DIRECTIVE_CTX
S_TTFF = F_ALLOW_IN | F_FUNC_BODY