import re

from astconv.convutils.code import *
from astconv.constant import *
from astconv.convutils.Syntax import Syntax

exports = dict(
    # version = require('./package.json').version;
    browser=False,
)

# Global variables
SourceNode = None
estraverse = None
_base = None
indent = None
_json = None
renumber = None
hexadecimal = None
quotes = None
escapeless = None
newline = None
space = None
parentheses = None
semicolons = None
safeConcatenation = None
directive = None
extra = None
parse = None
sourceMap = None
sourceCode = None
preserveBlankLines = None
FORMAT_MINIFY = None
FORMAT_DEFAULTS = None


def isExpression(node):
    return node['type'] in CodeGenerator.Expression


def isStatement(node):
    return node['type'] in CodeGenerator.Statement


def getDefaultOptions():
    return dict(
        indent=None,
        base=None,
        parse=None,
        comment=True,
        format=dict(
            indent=dict(
                style='    ',
                base=0,
                adjustMultilineComment=False,
            ),
            newline='\n',
            space=' ',
            json=False,
            renumber=False,
            hexadecimal=False,
            quotes='single',
            escapeless=False,
            compact=False,
            parentheses=True,
            semicolons=True,
            safeConcatenation=False,
            preserveBlankLines=False
        ),
        moz=dict(
            comprehensionExpressionStartsWithAssignment=False,
            starlessGenerator=False
        ),
        sourceMap=None,
        sourceMapRoot=None,
        sourceMapWithCode=False,
        directive=False,
        raw=True,
        verbatim=None,
        sourceCode=None
    )


def stringRepeat(_str, num):
    result = ''
    while num > 0:
        if num & 1:
            result += _str
        num >>= 1
        _str += _str
    return result


def hasLineTerminator(_str):
    pattern = re.compile('/[\r\n]/')
    return pattern.match(_str)


def endsWithLineTerminator(_str):
    return len(_str) and isLineTerminator(_str[-1])


def merge(target, override):
    for key in override.keys():
        target[key] = override[key]
    return target


def updateDeeply(target, override):
    def isHashObject(tar):
        return type(tar) == dict

    for key in override.keys():
        val = override[key]
        if isHashObject(val):
            if isHashObject(target[key]):
                updateDeeply(target[key], val)
            else:
                target[key] = updateDeeply({}, val)
        else:
            target[key] = val
    return target


def generateNumber(value):
    if value is None:
        raise Exception('Numeric literal whose value is NaN')
    if value < 0:
        raise Exception('Numeric literal whose value is negative')
    if value == float('Inf'):
        return 'null' if _json else '1e400' if renumber else '1e+400'
    result = str(value)
    if not renumber or len(result) < 3:
        return result
    point = result.index('.')
    if not _json and ord(result[0]) == 0x30 and point == 1:
        point = 0
        result = result[1:]
    temp = result
    result = result.replace('e+', 'e')
    exponent = 0
    pos = temp.index('e')
    if pos > 0:
        exponent = int(temp[pos + 1])
        temp = temp[0:pos]
    if point > 0:
        exponent -= len(temp) - point - 1
        temp = str(int(temp[0:point] + temp[point + 1:]))
    pos = 0
    while ord(temp[len(temp) + pos - 1]) == 0x30:
        pos -= 1
    if pos != 0:
        exponent -= pos
        temp = temp[0:pos]
    if exponent != 0:
        temp += 'e' + str(exponent)
    if len(temp) < len(result) or (
            hexadecimal and 1e12 < value == int(value) and
            (len('0x' + str(hex(value))) < len(result))) and int(temp) == value:
        result = '0x' + str(value)
    return result


def escapeRegExpCharacter(ch, previousIsBackslash):
    if (ch & ~1) == 0x2028:
        return ('u' if previousIsBackslash else '\\u') + ('2028' if ch == 0x2028 else '2029')
    elif ch == 10 or ch == 13:
        return ('' if previousIsBackslash else '\\') + ('n' if ch == 10 else 'r')
    return chr(ch)


def generateRegExp(reg):
    result = str(reg)
    pattern = re.compile('/\/([^/]*)$/')
    if reg.source:
        match = pattern.match(result)
        if not match:
            return result
        flags = match[1]
        result = ''

        characterInBrack = False
        previousIsBackslash = False
        for i in range(len(reg.source)):
            ch = ord(reg.source[i])
            if not previousIsBackslash:
                if characterInBrack:
                    if ch == 93:
                        characterInBrack = False
                else:
                    if ch == 47:
                        result += '\\'
                    elif ch == 91:
                        characterInBrack = True
                result += escapeRegExpCharacter(ch, previousIsBackslash)
                previousIsBackslash = (ch == 92)
            else:
                result += escapeRegExpCharacter(ch, previousIsBackslash)
                previousIsBackslash = False
        return '/' + result + '/' + str(flags)
    return result


def escapeAllowedCharacter(code, next):
    if code == 0x08:
        return '\b'

    if code == 0x0C:
        return '\f'

    if code == 0x09:
        return '\t'

    _hex = str(hex(code)).upper()
    if _json or code > 0xFF:
        return '\\u' + '0000'[len(_hex):] + _hex
    elif code == 0x0000 and not isDecimalDigit(next):
        return '\\0'
    elif code == 0x000B:
        return '\\x0B'
    else:
        return '\\x' + '00'[len(_hex)] + _hex


def escapeDisallowedCharacter(code):
    if code == 0x5C:
        return '\\'
    if code == 0x0A:
        return '\n'
    if code == 0x0D:
        return '\r'
    if code == 0x2028:
        return '\u2028'
    if code == 0x2029:
        return '\u2029'
    raise Exception('Incorrectly classified character')


def escapeDirective(_str):
    quote = '"' if quotes == 'double' else '\''
    for i in range(len(_str)):
        code = ord(_str[i])
        if code == 0x27:
            quote = '"'
            break
        elif code == 0x22:
            quote = '\''
            break
        elif code == 0x5C:
            i += 1
    return quote + _str + quote


def escapeString(_str):
    result = ''
    singleQuotes = 0
    doubleQuotes = 0
    for i in range(len(_str)):
        code = ord(_str[i])
        if code == 0x27:
            singleQuotes += 1
        elif code == 0x22:
            doubleQuotes += 1
        elif code == 0x2F:
            result += '\\'
        elif isLineTerminator(code) or code == 0x5C:
            result += escapeDisallowedCharacter(code)
            continue
        elif not isIdentifierPartES5(code) and (_json and code < 0x20 or not _json and
                                                not escapeless and (code < 0x20 or code > 0x7E)):
            result += escapeAllowedCharacter(code, ord(_str[i + 1]))
            continue
        result += chr(code)

    single = not (quotes == 'double' or (quotes == 'auto' and doubleQuotes < singleQuotes))
    quote = '\'' if single else '"'
    if not (singleQuotes if single else doubleQuotes):
        return quote + result + quote
    _str = result
    result = quote
    for i in range(len(_str)):
        code = ord(_str[i])
        if code == 0x27:
            result += '\\'
        result += chr(code)
    return result + quote


def flattenToString(arr):
    result = ''
    for i in range(len(arr)):
        elem = arr[i]
        result += flattenToString(elem) if type(elem) is list else elem
    return result


def toSourceNodeWhenNeeded(generated, node=None):
    if not sourceMap:
        if type(generated) is list:
            return flattenToString(generated)
        else:
            return generated
    if node is None:
        if isinstance(generated, SourceNode):
            return generated
        else:
            node = {}
    if 'loc' in node and node['loc'] is None:
        return SourceNode(None, None, sourceMap, generated, node['name'] or None)
    return SourceNode(node['loc']['start']['line'], node['loc']['start']['column'],
                      ((node['loc']['source'] or None) if sourceMap == True else sourceMap), generated,
                      node['name'] or None)


def noEmptySpace():
    return space if space else ' '


def join(left, right):
    leftSource = str(toSourceNodeWhenNeeded(left))
    if len(leftSource) == 0:
        return [right]

    rightSource = str(toSourceNodeWhenNeeded(right))
    if len(rightSource) == 0:
        return [left]

    leftCharCode = ord(leftSource[-1])
    rightCharCode = ord(rightSource[0])

    if (leftCharCode == 0x2B or leftCharCode == 0x2D) and leftCharCode == rightCharCode or \
            isIdentifierPartES5(leftCharCode) and isIdentifierPartES5(rightCharCode) or \
            leftCharCode == 0x2F and rightCharCode == 0x69:
        return [left, noEmptySpace(), right]
    elif isWhiteSpace(leftCharCode) or isLineTerminator(leftCharCode) or \
            isWhiteSpace(rightCharCode) or isLineTerminator(rightCharCode):
        return [left, right]
    return [left, space, right]


def addIndent(stmt):
    return [_base, stmt]


def calculateSpaces(_str):
    global i
    for i in range(len(_str) - 1, -1, -1):
        if isLineTerminator(_str[i]):
            break
    return len(_str) - i


def adjustMultilineComment(value, specialBase):
    array = value.split('/\r\n|[\r\n]/')
    spaces = 9007199254740991
    global _base
    for line in array:
        j = 0
        while j < len(line) and isWhiteSpace(line[j]):
            j += 1
        if spaces > j:
            spaces = j

    if specialBase is not None:
        previousBase = _base
        if array[1][spaces] == '*':
            specialBase += ' '
        _base = specialBase
    else:
        if spaces & 1:
            spaces -= 1
        previousBase = _base

    for i in range(0, len(array)):
        sn = toSourceNodeWhenNeeded(addIndent(array[i].slice(spaces)))
        array[i] = sn.join('') if sourceMap else sn

    _base = previousBase
    return array.join('\n')


def generateComment(comment, specialBase=None):
    pattern = re.compile(r'/[\n\r]/')
    if comment['type'] == 'Line':
        if endsWithLineTerminator(comment['value']):
            return '//' + comment.value
        else:
            result = '//' + comment.value
            if not preserveBlankLines:
                result += '\n'
            return result
    if extra['format']['indent.']['adjustMultilineComment'] and pattern.match(comment['value']):
        return adjustMultilineComment('/*' + comment['value'] + '*/', specialBase)
    return '/*' + comment['value'] + '*/'


def addComments(stmt, result):
    pattern = re.compile(r'/\n/')
    if 'leadingComments' in stmt and len(stmt['leadingComments']) > 0:
        save = result
        if preserveBlankLines:
            comment = stmt['leadingComments'][0]
            result = []

            extRange = comment['extendedRange']
            _range = comment['range']

            prefix = sourceCode[extRange[0]:_range[0]]
            count = len(pattern.match(prefix) or [])
            if count > 0:
                result.append(stringRepeat('\n', count))
                result.append(addIndent(generateComment(comment)))
            else:
                result.append(prefix)
                result.append(generateComment(comment))

            prevRange = _range

            for i in range(1, len(stmt['leadingComments'])):
                comment = stmt['leadingComments'][i]
                _range = comment['range']

                infix = sourceCode[prevRange[1]:_range[0]]
                count = len(pattern.match(infix) or [])
                result.append(stringRepeat('\n', count))
                result.append(addIndent(generateComment(comment)))

                prevRange = _range

            suffix = sourceCode[_range[1]:extRange[1]]
            count = len(pattern.match(suffix) or [])
            result.append(stringRepeat('\n', count))
        else:
            comment = stmt['leadingComments'][0]
            result = []
            if safeConcatenation and stmt['type'] == Syntax['Program'] and len(stmt['body'].length) == 0:
                result.append('\n')
            result.append(generateComment(comment))
            if not endsWithLineTerminator(str(toSourceNodeWhenNeeded(result).toString())):
                result.append('\n')

            for i in range(1, len(stmt['leadingComments'])):
                comment = stmt['leadingComments'][i]
                fragment = [generateComment(comment)]
                if not endsWithLineTerminator(str(toSourceNodeWhenNeeded(fragment))):
                    fragment.append('\n')
                result.append(addIndent(fragment))

        result.append(addIndent(save))
    if 'trailingComments' in stmt:
        if preserveBlankLines:
            comment = stmt['trailingComments'][0]
            extRange = comment['extendedRange']
            _range = comment['range']

            prefix = sourceCode[extRange[0]:_range[0]]
            count = len(pattern.match(prefix) or [])

            if count > 0:
                result.append(stringRepeat('\n', count))
                result.append(addIndent(generateComment(comment)))
            else:
                result.push(prefix)
                result.push(generateComment(comment))
        else:
            tailingToStatement = not endsWithLineTerminator(str(toSourceNodeWhenNeeded(result)))
            specialBase = stringRepeat(' ', calculateSpaces(str(toSourceNodeWhenNeeded([_base, result, indent]))))
            for i in range(0, len(stmt['trailingComments'])):
                comment = stmt['trailingComments'][i]
                if tailingToStatement:
                    if i == 0:
                        result = [result, indent]
                    else:
                        result = [result, specialBase]
                    result.append(generateComment(comment, specialBase))
                else:
                    result = [result, addIndent(generateComment(comment))]
                if i != len(stmt['trailingComments']) - 1 and not endsWithLineTerminator(
                        str(toSourceNodeWhenNeeded(result))):
                    result = [result, '\n']
    return result


def generateBlankLines(start, end, result):
    newlineCount = 0
    for j in range(start, end):
        if sourceCode[j] == '\n':
            newlineCount += 1

    for j in range(1, newlineCount):
        result.append(newline)


def parenthesize(text, current, should):
    if current < should:
        return ['(', text, ')']
    return text


def generateVerbatimString(string):
    result = string.split('/\r\n|\n/')
    for i in range(0, len(result)):
        result[i] = newline + str(_base) + result[i]
    return result


def generateVerbatim(expr, precedence):
    verbatim = expr[extra['verbatim']]

    if type(verbatim) == str:
        result = parenthesize(generateVerbatimString(verbatim), Precedence['Sequence'], precedence)
    else:
        result = generateVerbatimString(verbatim['content'])
        prec = verbatim['precedence'] if verbatim['precedence'] is not None else Precedence['Sequence']
        result = parenthesize(result, prec, precedence)
    return toSourceNodeWhenNeeded(result, expr)


def generateIdentifier(node):
    return toSourceNodeWhenNeeded(node['name'], node)


def generateAsyncPrefix(node, spaceRequired):
    return 'async' + (noEmptySpace() if spaceRequired else space) if node['async'] else ''


def generateStarSuffix(node):
    isGenerator = node['generator'] and not extra['moz']['starlessGenerator']
    return '*' + str(space) if isGenerator else ''


def generateMethodPrefix(prop):
    func = prop['value']
    prefix = ''
    if func['async']:
        prefix += generateAsyncPrefix(func, not prop['computed'])
    if func['generator']:
        prefix += '*' if generateStarSuffix(func) else ''
    return prefix


class CodeGenerator(object):
    Statement = [
        'BlockStatement', 'BreakStatement', 'ContinueStatement', 'ClassBody', 'ClassDeclaration', 'DirectiveStatement',
        'DoWhileStatement', 'CatchClause', 'DebuggerStatement', 'EmptyStatement', 'ExportDefaultDeclaration',
        'ExportNamedDeclaration',
        'ExportAllDeclaration',
        'ExpressionStatement',
        'ImportDeclaration',
        'VariableDeclarator',
        'VariableDeclaration',
        'ThrowStatement',
        'TryStatement',
        'SwitchStatement',
        'SwitchCase',
        'IfStatement',
        'ForStatement',
        'ForInStatement',
        'ForOfStatement',
        'LabeledStatement',
        'Program',
        'FunctionDeclaration',
        'ReturnStatement',
        'WhileStatement',
        'WithStatement',
        '',
    ]

    def generatePattern(self, node, precedence, flags):
        if node['type'] == Syntax['Identifier']:
            return generateIdentifier(node)
        return self.generateExpression(node, precedence, flags)

    def generateFunctionParams(self, node):
        hasDefault = False
        if node['type'] == Syntax['ArrowFunctionExpression'] and 'rest' in node and not node['rest'] and (
                'defaults' not in node or len(node['defaults']) == 0) and len(node['params']) == 1 and \
                node['params'][0]['type'] == Syntax['Identifier']:
            result = [generateAsyncPrefix(node, True), generateIdentifier(node['params'][0])]
        else:
            result = [generateAsyncPrefix(node, False)] if node['type'] == Syntax['ArrowFunctionExpression'] else []
            result.append('(')
        if 'defaults' in node and node['defaults']:
            hasDefault = True
        for i in range(len(node['params'])):
            if hasDefault and node['defaults'][i]:
                result.append(
                    self.generateAssignment(node['params'][i], node['defaults'][i], '=', Precedence['Assignment'],
                                            E_TTT))
            else:
                result.append(self.generatePattern(node['params'][i], Precedence['Assignment'], E_TTT))
            if i + 1 < len(node['params']):
                result.append(',' + space)
        if 'rest' in node and node['rest']:
            if len(node['params']):
                result.append(',' + space)
            result.append('...')
            result.append(generateIdentifier(node['rest']))
        result.append(')')
        return result

    def generateFunctionBody(self, node):
        result = self.generateFunctionParams(node)
        if node['type'] == Syntax['ArrowFunctionExpression']:
            result.append(space)
            result.append('=>')
        if 'expression' in node and node['expression']:
            result.append(space)
            expr = self.generateExpression(node['body'], Precedence['Assignment'], E_TTT)
            if str(expr)[0] == '{':
                expr = ['(', expr, ')']
            result.append(expr)
        else:
            result.append(self.maybeBlock(node['body'], S_TTFF))
        return result

    def generateIterationForStatement(self, operator, stmt, flags):
        result = ['for' + space + ('await' + space if 'await' in stmt else '') + '(']
        that = self
        global _base
        previousBase = _base
        _base += indent
        # base = previousBase
        if stmt['left']['type'] == Syntax['VariableDeclaration']:
            pBase = _base
            _base += indent
            result.append(stmt['left']['kind'] + noEmptySpace())
            result.append(that.generateStatement(stmt['left']['declarations'][0], S_FFFF))
            _base = pBase
        else:
            result.append(that.generateExpression(stmt['left'], Precedence['Call'], E_TTT))

        result = join(result, operator)
        result = [join(
            result, that.generateExpression(stmt['right'], Precedence['Assignment'], E_TTT)), ')']
        _base = previousBase
        result.append(self.maybeBlock(stmt['body'], flags))
        return result

    def generatePropertyKey(self, expr, computed):
        result = []
        if computed:
            result.append('[')
        result.append(self.generateExpression(expr, Precedence['Sequence'], E_TTT))
        if computed:
            result.append(']')
        return result

    def generateAssignment(self, left, right, operator, precedence, flags):
        if Precedence['Assignment'] < precedence:
            flags |= F_ALLOW_IN

        return parenthesize(
            [
                self.generateExpression(left, Precedence['Call'], flags),
                space + operator + space,
                self.generateExpression(right, Precedence['Assignment'], flags)
            ],
            Precedence['Assignment'],
            precedence
        )

    def semicolon(self, flags):
        if not semicolons and flags & F_SEMICOLON_OPT:
            return ''
        return ';'

    # statements
    def BlockStatement(self, stmt, flags):
        result = ['{', newline]
        that = self
        global _base
        previousBase = _base
        if len(stmt['body']) == 0 and preserveBlankLines:
            _range = stmt['range']
            if _range[1] - _range[0] > 2:
                content = sourceCode[_range[0] + 1:_range[1] - 1]
                if content[0] == '\n':
                    result = ['{']
                result.append(content)

        bodyFlags = S_TFFF
        if flags & F_FUNC_BODY:
            bodyFlags |= F_DIRECTIVE_CTX
        iz = len(stmt['body'])
        for i in range(iz):
            if preserveBlankLines:
                if i == 0:
                    if 'leadingComments' in stmt['body'][0]:
                        _range = stmt['body'][0]['leadingComments'][0]['extendedRange']
                        content = sourceCode[_range[0]: _range[1]]
                        if content[0] == '\n':
                            result = ['{']
                    if 'leadingComments' not in stmt['body'][0]:
                        generateBlankLines(stmt['range'][0], stmt['body'][0]['range'][0], result)

                if i > 0:
                    if 'trailingComments' not in stmt['body'][i - 1] and 'leadingComments' not in stmt['body'][i]:
                        generateBlankLines(stmt['body'][i - 1]['range'][1], stmt['body'][i]['range'][0], result)

            if i == iz - 1:
                bodyFlags |= F_SEMICOLON_OPT

            if 'leadingComments' in stmt['body'][i] and stmt['body'][i]['leadingComments'] and preserveBlankLines:
                fragment = that.generateStatement(stmt['body'][i], bodyFlags)
            else:
                fragment = addIndent(that.generateStatement(stmt['body'][i], bodyFlags))

            result.append(fragment)
            if not endsWithLineTerminator(str(toSourceNodeWhenNeeded(fragment))):
                if preserveBlankLines and i < iz - 1:
                    if not stmt['body'][i + 1]['leadingComments']:
                        result.append(newline)
                else:
                    result.append(newline)

            if preserveBlankLines:
                if i == iz - 1:
                    if 'trailingComments' not in stmt['body'][i]:
                        generateBlankLines(stmt['body'][i]['range'][1], stmt['range'][1], result)
        _base = previousBase
        result.append(addIndent('}'))
        return result

    def BreakStatement(self, stmt, flags):
        if 'label' in stmt and stmt['label']:
            return 'break ' + stmt['label']['name'] + self.semicolon(flags)
        return 'break' + self.semicolon(flags)

    def ContinueStatement(self, stmt, flags):
        if 'label' in stmt and stmt['label']:
            return 'continue ' + stmt['label']['name'] + self.semicolon(flags)
        return 'continue' + self.semicolon(flags)

    def ClassBody(self, stmt, flags=None):
        result = ['{', newline]
        that = self

        global _base
        previousBase = _base
        iz = len(stmt['body'])
        for i in range(iz):
            result.append(indent)
            result.append(that.generateExpression(stmt['body'][i], Precedence['Sequence'], E_TTT))
            if i + 1 < iz:
                result.append(newline)

        _base = previousBase
        if not endsWithLineTerminator(str(toSourceNodeWhenNeeded(result))):
            result.append(newline)
        result.append(_base)
        result.append('}')
        return result

    def ClassDeclaration(self, stmt, flags=None):
        result = ['class']
        if stmt['id']:
            result = join(result, self.generateExpression(stmt['id'], Precedence['Sequence'], E_TTT))
        if stmt['superClass']:
            fragment = join('extends', self.generateExpression(stmt['superClass'], Precedence['Assignment'], E_TTT))
            result = join(result, fragment)
        result.append(space)
        result.append(self.generateStatement(stmt.body, S_TFFT))
        return result

    def DirectiveStatement(self, stmt, flags):
        if extra['raw'] and stmt['raw']:
            return stmt['raw'] + self.semicolon(flags)
        return escapeDirective(stmt['directive']) + self.semicolon(flags)

    def DoWhileStatement(self, stmt, flags):
        result = join('do', self.maybeBlock(stmt['body'], S_TFFF))
        result = self.maybeBlockSuffix(stmt['body'], result)
        return join(result, [
            'while' + space + '(',
            self.generateExpression(stmt['test'], Precedence['Sequence'], E_TTT),
            ')' + self.semicolon(flags)
        ])

    def CatchClause(self, stmt, flgas=None):
        that = self
        global _base
        previousBase = _base
        _base += indent
        result = [
            'catch' + space + '(',
            that.generateExpression(stmt['param'], Precedence['Sequence'], E_TTT),
            ')'
        ]

        if 'guard' in stmt:
            guard = that.generateExpression(stmt['guard'], Precedence['Sequence'], E_TTT)
            result.insert(2, ' if ')
            result.insert(3, guard)
        _base = previousBase
        result.append(self.maybeBlock(stmt['body'], S_TFFF))
        return result

    def DebuggerStatement(self, stmt, flags):
        return 'debugger' + self.semicolon(flags)

    def EmptyStatement(self, stmt=None, flags=None):
        return ';'

    def ExportDefaultDeclaration(self, stmt, flags):
        result = ['export']
        bodyFlags = S_TFFT if flags & F_SEMICOLON_OPT else S_TFFF

        result = join(result, 'default')
        if isStatement(stmt['declaration']):
            result = join(result, self.generateStatement(stmt['declaration'], bodyFlags))
        else:
            result = join(result, self.generateExpression(stmt['declaration'], Precedence['Assignment'],
                                                          E_TTT) + self.semicolon(flags))
        return result

    def ExportNamedDeclaration(self, stmt, flags):
        result = ['export']
        that = self
        bodyFlags = S_TFFT if flags & F_SEMICOLON_OPT else S_TFFF
        if 'declaration' in stmt:
            return join(result, self.generateStatement(stmt['declaration'], bodyFlags))
        if 'specifiers' in stmt:
            if len(stmt['specifiers']) == 0:
                result = join(result, '{' + space + '}')
            elif stmt['specifiers'][0]['type'] == Syntax['ExportBatchSpecifier']:
                result = join(result, self.generateExpression(stmt['specifiers'][0], Precedence['Sequence'], E_TTT))
            else:
                global _base
                result = join(result, '{')
                previousBase = _base
                iz = len(stmt['specifiers'])
                result.append(newline)
                for i in range(iz):
                    result.append(indent)
                    result.append(that.generateExpression(stmt['specifiers'][i], Precedence['Sequence'], E_TTT))
                    if i + 1 < iz:
                        result.append(',' + newline)
                _base = previousBase
                if not endsWithLineTerminator(str(toSourceNodeWhenNeeded(result))):
                    result.append(newline)
                result.append(_base + '}')

            if 'source' in stmt and stmt['source']:
                result = join(result, [
                    'from' + space,
                    self.generateExpression(stmt['source'], Precedence['Sequence'], E_TTT),
                    self.semicolon(flags)
                ])
            else:
                result.append(self.semicolon(flags))
        return result

    def ExportAllDeclaration(self, stmt, flags):
        return [
            'export' + space,
            '*' + space,
            'from' + space,
            self.generateExpression(stmt['source'], Precedence['Sequence'], E_TTT),
            self.semicolon(flags)
        ]

    def ExpressionStatement(self, stmt, flags):
        def isClassPrefixed(fragment):
            if fragment[0: 5] != 'class':
                return False
            code = ord(fragment[5])
            return code == 0x7B or isWhiteSpace(code) or isLineTerminator(code)

        def isFunctionPrefixed(fragment):
            if fragment[0: 8] != 'function':
                return False
            code = ord(fragment[8])
            return code == 0x28 or isWhiteSpace(code) or code == 0x2A or isLineTerminator(
                code)

        def isAsyncPrefixed(fragment):
            if fragment[0: 5] != 'async':
                return False
            if not isWhiteSpace(ord(fragment[5])):
                return False
            iz = len(fragment)
            i = 0
            for i in range(iz):
                if not isWhiteSpace(ord(fragment[i])):
                    break
            if i == iz:
                return False
            if fragment[i, i + 8] != 'function':
                return False
            code = ord(fragment[i + 8])
            return code == 0x28 or isWhiteSpace(code) or code == 0x2A or isLineTerminator(
                code)

        result = [self.generateExpression(stmt['expression'], Precedence['Sequence'], E_TTT)]
        fragment = str(toSourceNodeWhenNeeded(result))
        if ord(fragment[0]) == 0x7B or isClassPrefixed(fragment) or isFunctionPrefixed(fragment) or isAsyncPrefixed(
                fragment) or (
                directive and (flags & F_DIRECTIVE_CTX) and stmt['expression']['type'] == Syntax['Literal'] and type(
            stmt['expression']['value']) == str):
            result = ['(', result, ')' + self.semicolon(flags)]
        else:
            result.append(self.semicolon(flags))
        return result

    def ImportDeclaration(self, stmt, flags):
        that = self
        if len(stmt['specifiers']) == 0:
            return [
                'import',
                space,
                self.generateExpression(stmt['source'], Precedence['Sequence'], E_TTT),
                self.semicolon(flags)
            ]

        result = ['import']
        cursor = 0
        if stmt['specifiers'][cursor]['type'] == Syntax['ImportDefaultSpecifier']:
            result = join(result, [
                self.generateExpression(stmt['specifiers'][cursor], Precedence['Sequence'], E_TTT)
            ])
            cursor += 1
        if stmt['specifiers'][cursor]:
            if cursor != 0:
                result.append(',')
            if stmt['specifiers'][cursor]['type'] == Syntax['ImportNamespaceSpecifier']:
                result = join(result, [
                    space,
                    self.generateExpression(stmt['specifiers'][cursor], Precedence['Sequence'], E_TTT)
                ])
            else:
                result.append(space + '{')
                if len(stmt['specifiers']) - cursor == 1:
                    result.append(space)
                    result.append(self.generateExpression(stmt['specifiers'][cursor], Precedence['Sequence'], E_TTT))
                    result.append(space + '}' + space)
                else:
                    global _base
                    previousBase = _base
                    result.append(newline)
                    iz = len(stmt['specifiers'])
                    for i in range(iz):
                        result.append(indent)
                        result.append(that.generateExpression(stmt['specifiers'][i], Precedence['Sequence'], E_TTT))
                        if i + 1 < iz:
                            result.append(',' + newline)
                    _base = previousBase
                    if not endsWithLineTerminator(str(toSourceNodeWhenNeeded(result))):
                        result.append(newline)
                    result.append(_base + '}' + space)
        result = join(result, [
            'from' + space,
            self.generateExpression(stmt['source'], Precedence['Sequence'], E_TTT),
            self.semicolon(flags)
        ])
        return result

    def VariableDeclarator(self, stmt, flags):
        itemFlags = E_TTT if flags & F_ALLOW_IN else E_FTT
        if 'init' in stmt and stmt['init']:
            return [
                self.generateExpression(stmt['id'], Precedence['Assignment'], itemFlags),
                space,
                '=',
                space,
                self.generateExpression(stmt['init'], Precedence['Assignment'], itemFlags)
            ]
        return self.generatePattern(stmt['id'], Precedence['Assignment'], itemFlags);

    def VariableDeclaration(self, stmt, flags):
        that = self
        result = [stmt['kind']]
        bodyFlags = S_TFFF if flags & F_ALLOW_IN else S_FFFF
        if len(stmt['declarations']) > 1:
            global _base
            previousBase = _base
            _base += indent
            node = stmt['declarations'][0]
            if extra['comment'] and 'leadingComments' in node and node['leadingComments']:
                result.append('\n')
                result.append(addIndent(that.generateStatement(node, bodyFlags)))
            else:
                result.append(noEmptySpace())
                result.append(that.generateStatement(node, bodyFlags))
            iz = len(stmt['declarations'])
            for i in range(1, iz):
                node = stmt['declarations'][i]
                if extra['comment'] and 'leadingComments' in node and node['leadingComments']:
                    result.append(',' + newline)
                    result.append(addIndent(that.generateStatement(node, bodyFlags)))
                else:
                    result.append(',' + space)
                    result.append(that.generateStatement(node, bodyFlags))
            _base = previousBase
        else:
            node = stmt['declarations'][0]
            if extra['comment'] and 'leadingComments' in node and node['leadingComments']:
                result.append('\n')
                result.append(addIndent(that.generateStatement(node, bodyFlags)))
            else:
                result.append(noEmptySpace())
                result.append(that.generateStatement(node, bodyFlags))
            iz = len(stmt['declarations'])
            for i in range(1, iz):
                node = stmt['declarations'][i]
                if extra['comment'] and 'leadingComments' in node and node['leadingComments']:
                    result.append(',' + newline)
                    result.append(addIndent(that.generateStatement(node, bodyFlags)))
                else:
                    result.append(',' + space)
                    result.append(that.generateStatement(node, bodyFlags))
        result.append(self.semicolon(flags))
        return result

    def ThrowStatement(self, stmt, flags):
        return [join(
            'throw',
            self.generateExpression(stmt['argument'], Precedence['Sequence'], E_TTT)
        ), self.semicolon(flags)]

    def TryStatement(self, stmt, flags=None):
        result = ['try', self.maybeBlock(stmt['block'], S_TFFF)]
        result = self.maybeBlockSuffix(stmt['block'], result)
        if 'handlers' in stmt and stmt['handlers']:
            iz = len(stmt['handlers'])
            for i in range(iz):
                result = join(result, self.generateStatement(stmt['handlers'][i], S_TFFF))
                if 'finalizer' in stmt and stmt['finalizer'] or i + 1 != iz:
                    result = self.maybeBlockSuffix(stmt['handlers'][i]['body'], result)
        else:
            guardedHandlers = stmt['guardedHandlers'] if 'guardedHandlers' in stmt else []
            iz = len(guardedHandlers)
            for i in range(iz):
                result = join(result, self.generateStatement(guardedHandlers[i], S_TFFF))
                if ('finalizer' in stmt and stmt['finalizer']) or i + 1 != iz:
                    result = self.maybeBlockSuffix(guardedHandlers[i]['body'], result)
            if 'handler' in stmt and stmt['handler']:
                if type(stmt['handler']) == list:
                    iz = len(stmt['handler'])
                    for i in range(iz):
                        result = join(result, self.generateStatement(stmt['handler'][i], S_TFFF))
                        if stmt['finalizer'] or i + 1 != iz:
                            result = self.maybeBlockSuffix(stmt['handler'][i]['body'], result)
                else:
                    result = join(result, self.generateStatement(stmt['handler'], S_TFFF))
                    if 'finalizer' in stmt and stmt['finalizer']:
                        result = self.maybeBlockSuffix(stmt['handler']['body'], result)
        if 'finalizer' in stmt and stmt['finalizer']:
            result = join(result, ['finally', self.maybeBlock(stmt['finalizer'], S_TFFF)])
        return result

    def SwitchStatement(self, stmt, flags=None):
        that = self
        global _base
        previousBase = _base
        _base += indent
        result = [
            'switch' + space + '(',
            that.generateExpression(stmt['discriminant'], Precedence['Sequence'], E_TTT),
            ')' + space + '{' + newline
        ]
        _base = previousBase
        if 'cases' in stmt:
            bodyFlags = S_TFFF
            iz = len(stmt['cases'])
            for i in range(iz):
                if i == iz - 1:
                    bodyFlags |= F_SEMICOLON_OPT
                fragment = addIndent(self.generateStatement(stmt['cases'][i], bodyFlags))
                result.append(fragment)
                if not endsWithLineTerminator(str(toSourceNodeWhenNeeded(fragment))):
                    result.append(newline)
        result.append(addIndent('}'))
        return result

    def SwitchCase(self, stmt, flags):
        that = self
        global _base
        previousBase = _base
        _base += indent
        if 'test' in stmt and stmt['test']:
            result = [
                join('case', that.generateExpression(stmt['test'], Precedence['Sequence'], E_TTT)),
                ':'
            ]
        else:
            result = ['default:']
        i = 0
        iz = len(stmt['consequent'])
        if iz and stmt['consequent'][0]['type'] == Syntax['BlockStatement']:
            fragment = that.maybeBlock(stmt['consequent'][0], S_TFFF)
            result.append(fragment)
            i = 1

        if i != iz and not endsWithLineTerminator(str(toSourceNodeWhenNeeded(result))):
            result.append(newline)

        bodyFlags = S_TFFF
        while i < iz:

            if i == iz - 1 and flags & F_SEMICOLON_OPT:
                bodyFlags |= F_SEMICOLON_OPT
            fragment = addIndent(that.generateStatement(stmt['consequent'][i], bodyFlags))
            result.append(fragment)
            if i + 1 != iz and not endsWithLineTerminator(str(toSourceNodeWhenNeeded(fragment))):
                result.append(newline)
            i += 1
        _base = previousBase
        return result

    def IfStatement(self, stmt, flags):
        that = self
        global _base
        previousBase = _base
        _base += indent
        result = [
            'if' + space + '(',
            that.generateExpression(stmt['test'], Precedence['Sequence'], E_TTT),
            ')'
        ]
        _base = previousBase
        semicolonOptional = flags & F_SEMICOLON_OPT
        bodyFlags = S_TFFF
        if semicolonOptional:
            bodyFlags |= F_SEMICOLON_OPT
        if 'alternate' in stmt and stmt['alternate']:
            result.append(self.maybeBlock(stmt['consequent'], S_TFFF))
            result = self.maybeBlockSuffix(stmt['consequent'], result)
            if stmt['alternate']['type'] == Syntax['IfStatement']:
                result = join(result, ['else ', self.generateStatement(stmt['alternate'], bodyFlags)])
            else:
                result = join(result, join('else', self.maybeBlock(stmt['alternate'], bodyFlags)))
        else:
            result.append(self.maybeBlock(stmt['consequent'], bodyFlags))
        return result

    def ForStatement(self, stmt, flags):
        that = self
        global _base
        previousBase = _base
        _base += indent
        result = ['for' + space + '(']
        if 'init' in stmt and stmt['init']:
            if stmt['init']['type'] == Syntax['VariableDeclaration']:
                result.append(that.generateStatement(stmt['init'], S_FFFF))
            else:
                result.append(that.generateExpression(stmt['init'], Precedence['Sequence'], E_FTT))
                result.append(';')
        else:
            result.append(';')
        if 'test' in stmt and stmt['test']:
            result.append(space)
            result.append(that.generateExpression(stmt['test'], Precedence['Sequence'], E_TTT))
            result.append(';')
        else:
            result.append(';')

        if 'update' in stmt and stmt['update']:
            result.append(space)
            result.append(that.generateExpression(stmt['update'], Precedence['Sequence'], E_TTT))
            result.append(')')
        else:
            result.append(')')
        _base = previousBase
        result.append(self.maybeBlock(stmt['body'], S_TFFT if flags & F_SEMICOLON_OPT else S_TFFF))
        return result

    def ForInStatement(self, stmt, flags):
        return self.generateIterationForStatement('in', stmt, S_TFFT if flags & F_SEMICOLON_OPT else S_TFFF)

    def ForOfStatement(self, stmt, flags):
        return self.generateIterationForStatement('of', stmt, S_TFFT if flags & F_SEMICOLON_OPT else S_TFFF)

    def LabeledStatement(self, stmt, flags):
        return [stmt['label']['name'] + ':',
                self.maybeBlock(stmt['body'], S_TFFT if flags & F_SEMICOLON_OPT else S_TFFF)]

    def Program(self, stmt, flags=None):
        iz = len(stmt['body'])
        result = ['\n' if safeConcatenation and iz > 0 else '']
        bodyFlags = S_TFTF
        for i in range(iz):
            if not safeConcatenation and i == iz - 1:
                bodyFlags |= F_SEMICOLON_OPT
            if preserveBlankLines:
                if i == 0:
                    if not stmt['body'][0]['leadingComments']:
                        generateBlankLines(stmt['range'][0], stmt['body'][i]['range'][0], result)
                if i > 0:
                    if not stmt['body'][i - 1]['trailingComments'] and not stmt['body'][i]['leadingComments']:
                        generateBlankLines(stmt['body'][i - 1]['range'][1], stmt['body'][i]['range'][0], result)

            fragment = addIndent(self.generateStatement(stmt['body'][i], bodyFlags))
            result.append(fragment)
            if i + 1 < iz and not endsWithLineTerminator(str(toSourceNodeWhenNeeded(fragment))):
                if preserveBlankLines:
                    if not stmt['body'][i + 1]['leadingComments']:
                        result.append(newline)
                else:
                    result.append(newline)

            if preserveBlankLines:
                if i == iz - 1:
                    if not stmt['body'][i]['trailingComments']:
                        generateBlankLines(stmt['body'][i]['range'][1], stmt['range'][1], result)
        return result

    def FunctionDeclaration(self, stmt, flags=None):
        return [
            generateAsyncPrefix(stmt, True),
            'function',
            generateStarSuffix(stmt) or noEmptySpace(),
            generateIdentifier(stmt['id']) if stmt['id'] else '',
            self.generateFunctionBody(stmt)
        ]

    def ReturnStatement(self, stmt, flags):
        if 'argument' in stmt and stmt['argument']:
            return [join(
                'return',
                self.generateExpression(stmt['argument'], Precedence['Sequence'], E_TTT)
            ), self.semicolon(flags)]
        return ['return' + self.semicolon(flags)]

    def WhileStatement(self, stmt, flags):
        that = self
        global _base
        previousBase = _base
        _base += indent
        result = [
            'while' + space + '(',
            that.generateExpression(stmt['test'], Precedence['Sequence'], E_TTT),
            ')'
        ]
        _base = previousBase
        result.append(self.maybeBlock(stmt['body'], S_TFFT if flags & F_SEMICOLON_OPT else S_TFFF))
        return result

    def WithStatement(self, stmt, flags):
        that = self
        global _base
        previousBase = _base
        _base += indent
        result = [
            'with' + space + '(',
            that.generateExpression(stmt['object'], Precedence['Sequence'], E_TTT),
            ')'
        ]
        _base = previousBase
        result.append(self.maybeBlock(stmt['body'], S_TFFT if flags & F_SEMICOLON_OPT else S_TFFF))
        return result

    # Expressions
    Expression = {
        'SequenceExpression',
        'AssignmentExpression',
        'ArrowFunctionExpression',
        'ConditionalExpression',
        'LogicalExpression',
        'BinaryExpression',
        'CallExpression',
        'NewExpression',
        'MemberExpression',
        'MetaProperty',
        'UnaryExpression',
        'YieldExpression',
        'AwaitExpression',
        'UpdateExpression',
        'FunctionExpression',
        'ArrayExpression',
        'ArrayPattern',
        'RestElement',
        'ClassExpression',
        'MethodDefinition',
        'Property',
        'ObjectExpression',
        'AssignmentPattern',
        'ObjectPattern',
        'ThisExpression',
        'Super',
        'Identifier',
        'ImportDefaultSpecifier',
        'ImportNamespaceSpecifier',
        'ImportSpecifier',
        'ExportSpecifier',
        'Literal',
        'GeneratorExpression',
        'ComprehensionExpression',
        'ComprehensionBlock',
        'SpreadElement',
        'TaggedTemplateExpression',
        'TemplateElement',
        'TemplateLiteral',
        'ModuleSpecifier',
    }

    def SequenceExpression(self, expr, precedence, flags):
        if Precedence['Sequence'] < precedence:
            flags |= F_ALLOW_IN
        result = []
        iz = len(expr['expressions'])
        for i in range(iz):
            result.append(self.generateExpression(expr['expressions'][i], Precedence['Assignment'], flags))
            if i + 1 < iz:
                result.append(',' + space)
        return parenthesize(result, Precedence['Sequence'], precedence)

    def AssignmentExpression(self, expr, precedence, flags):
        return self.generateAssignment(expr['left'], expr['right'], expr['operator'], precedence, flags)

    def ArrowFunctionExpression(self, expr, precedence, flags):
        return parenthesize(self.generateFunctionBody(expr), Precedence['ArrowFunction'], precedence)

    def ConditionalExpression(self, expr, precedence, flags):
        if Precedence['Conditional'] < precedence:
            flags |= F_ALLOW_IN

        return parenthesize(
            [
                self.generateExpression(expr['test'], Precedence['LogicalOR'], flags),
                space + '?' + space,
                self.generateExpression(expr['consequent'], Precedence['Assignment'], flags),
                space + ':' + space,
                self.generateExpression(expr['alternate'], Precedence['Assignment'], flags)
            ],
            Precedence['Conditional'],
            precedence
        )

    def LogicalExpression(self, expr, precedence, flags):
        return self.BinaryExpression(expr, precedence, flags)

    def BinaryExpression(self, expr, precedence, flags):
        currentPrecedence = BinaryPrecedence[expr['operator']]
        if currentPrecedence < precedence:
            flags |= F_ALLOW_IN
        fragment = self.generateExpression(expr['left'], currentPrecedence, flags)
        leftSource = str(fragment)
        if ord(leftSource[-1]) == 0x2F and isIdentifierPartES5(ord(expr['operator'][0])):
            result = [fragment, noEmptySpace(), expr['operator']]
        else:
            result = join(fragment, expr['operator'])

        fragment = self.generateExpression(expr['right'], currentPrecedence + 1, flags)

        if expr['operator'] == '/' and str(fragment)[0] == '/' or expr['operator'][-1] == '<' and str(fragment)[
                                                                                                  0: 3] == '!--':
            result.append(noEmptySpace())
            result.append(fragment)
        else:
            result = join(result, fragment)
        if expr['operator'] == 'in' and not (flags & F_ALLOW_IN):
            return ['(', result, ')']
        return parenthesize(result, currentPrecedence, precedence)

    def CallExpression(self, expr, precedence, flags):
        result = [self.generateExpression(expr['callee'], Precedence['Call'], E_TTF), '(']
        iz = len(expr['arguments'])
        for i in range(iz):
            result.append(self.generateExpression(expr['arguments'][i], Precedence['Assignment'], E_TTT))
            if i + 1 < iz:
                result.append(',' + space)
        result.append(')')
        if not (flags & F_ALLOW_CALL):
            return ['(', result, ')']
        return parenthesize(result, Precedence['Call'], precedence)

    def NewExpression(self, expr, precedence, flags):
        length = len(expr['arguments'])
        itemFlags = E_TFT if flags & F_ALLOW_UNPARATH_NEW and not parentheses and length == 0 else E_TFF
        result = join(
            'new',
            self.generateExpression(expr['callee'], Precedence['New'], itemFlags)
        )

        if not (flags & F_ALLOW_UNPARATH_NEW) or parentheses or length > 0:
            result.append('(')
            for i in range(length):
                result.append(self.generateExpression(expr['arguments'][i], Precedence['Assignment'], E_TTT))
                if i + 1 < length:
                    result.append(',' + space)
            result.append(')')
        return parenthesize(result, Precedence['New'], precedence)

    def MemberExpression(self, expr, precedence, flags):
        result = [self.generateExpression(expr['object'], Precedence['Call'], E_TTF if flags & F_ALLOW_CALL else E_TFF)]
        if 'computed' in expr and expr['computed']:
            result.append('[')
            result.append(self.generateExpression(expr['property'], Precedence['Sequence'],
                                                  E_TTT if flags & F_ALLOW_CALL else E_TFT))
            result.append(']')
        else:
            if expr['object']['type'] == Syntax['Literal'] and type(expr['object']['value']) in [int, float]:
                fragment = str(toSourceNodeWhenNeeded(result))
                pattern = re.compile('/[eExX]/')
                if '.' not in fragment and not pattern.match(fragment) and isDecimalDigit(
                        ord(fragment[-1])) and not (len(fragment) >= 2 and ord(fragment[0]) == 48):
                    result.append(' ')
            result.append('.')
            result.append(generateIdentifier(expr['property']))
        return parenthesize(result, Precedence['Member'], precedence)

    def MetaProperty(self, expr, precedence, flags=None):
        result = [expr['meta'] if type(expr['meta']) == str else generateIdentifier(expr['meta']), '.',
                  expr['property'] if type(expr['property']) == str else generateIdentifier(expr['property'])]
        return parenthesize(result, Precedence['Member'], precedence)

    def UnaryExpression(self, expr, precedence, flags=None):
        fragment = self.generateExpression(expr['argument'], Precedence['Unary'], E_TTT)
        if space == '':
            result = join(expr['operator'], fragment)
        else:
            result = [expr['operator']]
            if len(expr['operator']) > 2:
                result = join(result, fragment)
            else:
                leftSource = str(toSourceNodeWhenNeeded(result))
                leftCharCode = ord(leftSource[-1])
                rightCharCode = ord(str(fragment)[0])
                if (leftCharCode == 0x2B or leftCharCode == 0x2D and leftCharCode == rightCharCode) or (
                        isIdentifierPartES5(leftCharCode) and isIdentifierPartES5(
                    rightCharCode)):
                    result.append(noEmptySpace())
                    result.append(fragment)
                else:
                    result.append(fragment)
        return parenthesize(result, Precedence['Unary'], precedence)

    def YieldExpression(self, expr, precedence, flags=None):
        if 'delegate' in expr and expr['delegate']:
            result = 'yield*'
        else:
            result = 'yield'
        if 'argument' in expr and expr['argument']:
            result = join(
                result,
                self.generateExpression(expr['argument'], Precedence['Yield'], E_TTT)
            )
        return parenthesize(result, Precedence['Yield'], precedence)

    def AwaitExpression(self, expr, precedence, flags=None):
        result = join(
            'await*' if 'all' in expr else 'await',
            self.generateExpression(expr['argument'], Precedence['Await'], E_TTT)
        )
        return parenthesize(result, Precedence['Await'], precedence)

    def UpdateExpression(self, expr, precedence, flags=None):
        if 'prefix' in expr and expr['prefix']:
            return parenthesize(
                [
                    expr['operator'],
                    self.generateExpression(expr['argument'], Precedence['Unary'], E_TTT)
                ],
                Precedence['Unary'],
                precedence
            )
        return parenthesize(
            [
                self.generateExpression(expr['argument'], Precedence['Postfix'], E_TTT),
                expr['operator']
            ],
            Precedence['Postfix'],
            precedence
        )

    def FunctionExpression(self, expr, precedence, flags):
        result = [
            generateAsyncPrefix(expr, True),
            'function'
        ]
        if 'id' in expr and expr['id']:
            result.append(generateStarSuffix(expr) or noEmptySpace())
            result.append(generateIdentifier(expr['id']))
        else:
            result.append(generateStarSuffix(expr) or space)
        result.append(self.generateFunctionBody(expr))
        return result

    def ArrayPattern(self, expr, precedence, flags):
        return self.ArrayExpression(expr, precedence, flags, True)

    def ArrayExpression(self, expr, precedence, flags, isPattern=False):
        that = self
        if not len(expr['elements']):
            return '[]'
        multiline = False if isPattern else len(expr['elements']) > 1
        result = ['[', newline if multiline else '']
        global _base
        previousBase = _base
        _base += indent
        iz = len(expr['elements'])
        for i in range(iz):
            if not expr['elements'][i]:
                if multiline:
                    result.append(indent)
                if i + 1 == iz:
                    result.append(',')
            else:
                result.append(indent if multiline else '')
                result.append(that.generateExpression(expr['elements'][i], Precedence['Assignment'], E_TTT))
            if i + 1 < iz:
                result.append(',' + (newline if multiline else space))
        _base = previousBase
        if multiline and not endsWithLineTerminator(str(toSourceNodeWhenNeeded(result))):
            result.append(newline)
        result.append(_base if multiline else '')
        result.append(']')
        return result

    def RestElement(self, expr, precedence=None, flags=None):
        return '...' + self.generatePattern(expr['argument'])

    def ClassExpression(self, expr, precedence, flags):
        result = ['class']
        if 'id' in expr and expr['id']:
            result = join(result, self.generateExpression(expr['id'], Precedence['Sequence'], E_TTT))
        if 'superClass' in expr and expr['superClass']:
            fragment = join('extends', self.generateExpression(expr['superClass'], Precedence['Assignment'], E_TTT))
            result = join(result, fragment)
        result.append(space)
        result.append(self.generateStatement(expr['body'], S_TFFT))
        return result

    def MethodDefinition(self, expr, precedence, flags):
        if 'static' in expr and expr['static']:
            result = ['static' + space]
        else:
            result = []
        if expr['kind'] == 'get' or expr['kind'] == 'set':
            fragment = [
                join(expr['kind'], self.generatePropertyKey(expr['key'], expr['computed'])),
                self.generateFunctionBody(expr['value'])
            ]
        else:
            fragment = [
                generateMethodPrefix(expr),
                self.generatePropertyKey(expr['key'], expr['computed']),
                self.generateFunctionBody(expr['value'])
            ]
        return join(result, fragment)

    def Property(self, expr, precedence, flags):
        if expr['kind'] == 'get' or expr['kind'] == 'set':
            return [
                expr['kind'], noEmptySpace(),
                self.generatePropertyKey(expr['key'], expr['computed']),
                self.generateFunctionBody(expr['value'])
            ]

        if 'shorthand' in expr and expr['shorthand']:
            if expr['value']['type'] == "AssignmentPattern":
                return self.AssignmentPattern(expr['value'], Precedence['Sequence'], E_TTT)
            return self.generatePropertyKey(expr['key'], expr['computed'])

        if 'method' in expr and expr['method']:
            return [
                generateMethodPrefix(expr),
                self.generatePropertyKey(expr['key'], expr['computed']),
                self.generateFunctionBody(expr['value'])
            ]

        return [
            self.generatePropertyKey(expr['key'], expr['computed']),
            ':' + space,
            self.generateExpression(expr['value'], Precedence['Assignment'], E_TTT)
        ]

    def ObjectExpression(self, expr, precedence, flags):
        that = self
        if 'properties' not in expr or not expr['properties']:
            return '{}'
        multiline = len(expr['properties']) > 1
        global _base
        previousBase = _base
        _base += indent
        fragment = that.generateExpression(expr['properties'][0], Precedence['Sequence'], E_TTT)
        _base = previousBase
        if not multiline:
            if not hasLineTerminator(str(toSourceNodeWhenNeeded(fragment))):
                return ['{', space, fragment, space, '}']
        previousBase = _base
        _base += indent
        result = ['{', newline, indent, fragment]

        if multiline:
            result.append(',' + newline)
            iz = len(expr['properties'])
            for i in range(1, iz):
                result.append(indent)
                result.append(that.generateExpression(expr['properties'][i], Precedence['Sequence'], E_TTT))
                if i + 1 < iz:
                    result.append(',' + newline)
        _base = previousBase
        if not endsWithLineTerminator(str(toSourceNodeWhenNeeded(result))):
            result.append(newline)
        result.append(_base)
        result.append('}')
        return result

    def AssignmentPattern(self, expr, precedence, flags):
        return self.generateAssignment(expr['left'], expr['right'], '=', precedence, flags)

    def ObjectPattern(self, expr, precedence, flags):
        that = self
        if 'properties' not in expr:
            return '{}'

        multiline = False
        if len(expr['properties']) == 1:
            property = expr['properties'][0]
            if property['value']['type'] != Syntax['Identifier']:
                multiline = True
        else:
            for i in range(len(expr['properties'])):
                property = expr['properties'][i]
                if 'shorthand' not in property:
                    multiline = True
                    break
        result = ['{', newline if multiline else '']
        global _base
        previousBase = _base
        _base += indent
        iz = len(expr['properties'])
        for i in range(iz):
            result.append(indent if multiline else '')
            result.append(that.generateExpression(expr['properties'][i], Precedence['Sequence'], E_TTT))
            if i + 1 < iz:
                result.append(',' + (newline if multiline else space))
        _base = previousBase
        if multiline and not endsWithLineTerminator(str(toSourceNodeWhenNeeded(result))):
            result.append(newline)
        result.append(_base if multiline else '')
        result.append('}')
        return result

    def ThisExpression(self, expr, precedence, flags):
        return 'this'

    def Super(self, expr, precedence, flags):
        return 'super'

    def Identifier(self, expr, precedence, flags):
        return generateIdentifier(expr)

    def ImportDefaultSpecifier(self, expr, precedence, flags):
        return generateIdentifier(expr['id']) or expr['local']

    def ImportNamespaceSpecifier(self, expr, precedence, flags):
        result = ['*']
        id = expr['id'] if 'id' in expr else expr['local']
        if id:
            result.append(space + 'as' + noEmptySpace() + generateIdentifier(id))
        return result

    def ImportSpecifier(self, expr, precedence, flags):
        imported = expr['imported']
        result = [imported['name']]
        local = expr['local']
        if local and local['name'] != imported['name']:
            result.append(noEmptySpace() + 'as' + noEmptySpace() + generateIdentifier(local))
        return result

    def ExportSpecifier(self, expr, precedence, flags):
        local = expr['local']
        result = [local['name']]
        exported = expr['exported']
        if exported and exported['name'] != local['name']:
            result.append(noEmptySpace() + 'as' + noEmptySpace() + generateIdentifier(exported))
        return result

    def Literal(self, expr, precedence, flags):
        if 'raw' in expr and parse and extra['raw']:
            try:
                raw = parse(expr['raw'])['body'][0]['expression']
                if raw['type'] == Syntax['Literal']:
                    if raw['value'] == expr['value']:
                        return expr['raw']
            except:
                pass

        if 'value' not in expr:
            return 'null'

        if type(expr['value']) == str:
            return escapeString(expr['value'])

        if type(expr['value']) in [int, float]:
            return generateNumber(expr['value'])

        if type(expr['value']) == bool:
            return 'true' if expr['value'] else 'false'

        if 'regex' in expr and expr['regex']:
            return '/' + expr['regex']['pattern'] + '/' + expr['regex']['flags']
        return generateRegExp(expr['value'])

    def GeneratorExpression(self, expr, precedence, flags):
        return self.ComprehensionExpression(expr, precedence, flags)

    def ComprehensionExpression(self, expr, precedence, flags):
        that = self
        result = ['('] if expr['type'] == Syntax['GeneratorExpression'] else ['[']
        if extra['moz']['comprehensionExpressionStartsWithAssignment']:
            fragment = self.generateExpression(expr['body'], Precedence['Assignment'], E_TTT)
            result.append(fragment)
        if 'blocks' in expr and expr['blocks']:
            global _base
            previousBase = _base
            _base += indent
            for i in range(len(expr['blocks'])):
                fragment = that.generateExpression(expr['blocks'][i], Precedence['Sequence'], E_TTT)
                if i > 0 or extra['moz']['comprehensionExpressionStartsWithAssignment']:
                    result = join(result, fragment)
                else:
                    result.append(fragment)
            _base = previousBase

        if 'filter' in expr and expr['filter']:
            result = join(result, 'if' + space)
            fragment = self.generateExpression(expr['filter'], Precedence['Sequence'], E_TTT)
            result = join(result, ['(', fragment, ')'])

        if not extra['moz']['comprehensionExpressionStartsWithAssignment']:
            fragment = self.generateExpression(expr['body'], Precedence['Assignment'], E_TTT)
            result = join(result, fragment)

        result.append(')' if expr['type'] == Syntax['GeneratorExpression'] else ']')
        return result

    def ComprehensionBlock(self, expr, precedence, flags):
        if expr['left']['type'] == Syntax['VariableDeclaration']:
            fragment = [
                expr['left']['kind'], noEmptySpace(),
                self.generateStatement(expr['left']['declarations'][0], S_FFFF)
            ]
        else:
            fragment = self.generateExpression(expr['left'], Precedence['Call'], E_TTT)

        fragment = join(fragment, 'of' if expr['of'] else 'in')
        fragment = join(fragment, self.generateExpression(expr['right'], Precedence['Sequence'], E_TTT))

        return ['for' + space + '(', fragment, ')']

    def SpreadElement(self, expr, precedence, flags):
        return [
            '...',
            self.generateExpression(expr['argument'], Precedence['Assignment'], E_TTT)
        ]

    def TaggedTemplateExpression(self, expr, precedence, flags):
        itemFlags = E_TTF
        if not (flags & F_ALLOW_CALL):
            itemFlags = E_TFF

        result = [
            self.generateExpression(expr['tag'], Precedence['Call'], itemFlags),
            self.generateExpression(expr['quasi'], Precedence['Primary'], E_FFT)
        ]
        return parenthesize(result, Precedence['TaggedTemplate'], precedence)

    def TemplateElement(self, expr, precedence, flags):
        return expr['value']['raw']

    def TemplateLiteral(self, expr, precedence, flags):
        result = ['`']
        iz = len(expr['quasis'])
        for i in range(iz):
            result.append(self.generateExpression(expr['quasis'][i], Precedence['Primary'], E_TTT))
            if i + 1 < iz:
                result.append('${' + space)
                result.append(self.generateExpression(expr['expressions'][i], Precedence['Sequence'], E_TTT))
                result.append(space + '}')
        result.append('`')
        return result

    def ModuleSpecifier(self, expr, precedence, flags):
        return self.Literal(expr, precedence, flags)

    def generateExpression(self, expr, precedence, flags):
        _type = expr['type'] or Syntax['Property']
        if extra['verbatim'] and extra['verbatim'] in expr:
            return generateVerbatim(expr, precedence)
        result = getattr(self, _type)(expr, precedence, flags)
        if extra['comment']:
            result = addComments(expr, result)
        return toSourceNodeWhenNeeded(result, expr)

    def generateStatement(self, stmt, flags):
        result = getattr(self, stmt['type'])(stmt, flags)
        if extra['comment']:
            result = addComments(stmt, result)
        fragment = str(toSourceNodeWhenNeeded(result))
        if stmt['type'] == Syntax['Program'] and not safeConcatenation and newline == '' and fragment[-1] == '\n':
            result = re.sub(r"/\s+$/", '', toSourceNodeWhenNeeded(result)) if sourceMap else re.sub("/\s+$/", '',
                                                                                                    fragment)
        return toSourceNodeWhenNeeded(result, stmt)

    def maybeBlock(self, stmt, flags):
        global _base
        this = self
        noLeadingComment = not extra['comment'] or 'leadingComments' not in stmt
        if stmt['type'] == Syntax['BlockStatement'] and noLeadingComment:
            return [space, this.generateStatement(stmt, flags)]

        if stmt['type'] == Syntax['EmptyStatement'] and noLeadingComment:
            return ';'
        previousBase = _base
        _base = indent
        result = [newline, addIndent(this.generateStatement(stmt, flags))]
        _base = previousBase
        return result

    def maybeBlockSuffix(self, stmt, result):
        ends = endsWithLineTerminator(str(toSourceNodeWhenNeeded(result)))
        if stmt['type'] == Syntax['BlockStatement'] and (
                not extra['comment'] or 'leadingComments' not in stmt) and not ends:
            return [result, space]
        if ends:
            return [result, _base]
        return [result, newline, _base]

    def sequenceExpression(self, expr, precedence, flags):
        if Precedence['Sequence'] < precedence:
            flags |= F_ALLOW_IN
        result = []
        for i in range(len(expr['expressions'])):
            result.append(self.generateExpression(expr['expressions'][i], Precedence['Assignment'], flags))
            if i + 1 < len(expr['expressions']):
                result.append(',' + space)
        return parenthesize(result, Precedence['Sequence'], precedence)


def generateInternal(node):
    codegen = CodeGenerator()
    if isStatement(node):
        return codegen.generateStatement(node, S_TFFF)
    if isExpression(node):
        return codegen.generateExpression(node, Precedence['Sequence'], E_TTT)
    raise Exception('Unknown node type: ' + node['type'])


def flattenToString(arr):
    result = ''
    for i in range(0, len(arr)):
        elem = arr[i]
        result += flattenToString(elem) if type(elem) is list else elem
    return result


def generateInternal(node):
    codegen = CodeGenerator()
    if isStatement(node):
        return codegen.generateStatement(node, S_TFFF)

    if isExpression(node):
        return codegen.generateExpression(node, Precedence['Sequence'], E_TTT)

    raise Exception('Unknown node type: ' + node['type'])


def generate(node, options=None):
    global BinaryPrecedence
    global SourceNode
    global estraverse
    global _base
    global indent
    global _json
    global renumber
    global hexadecimal
    global quotes
    global escapeless
    global newline
    global space
    global parentheses
    global semicolons
    global safeConcatenation
    global directive
    global extra
    global parse
    global sourceMap
    global sourceCode
    global preserveBlankLines
    global FORMAT_MINIFY
    global FORMAT_DEFAULTS
    defaultOptions = getDefaultOptions()
    if options:
        if type(options['indent']) == str:
            defaultOptions['format']['indent']['style'] = options['indent']
        if type(options['base']) == int:
            defaultOptions['format']['indent']['base'] = options['base']
        options = updateDeeply(defaultOptions, options)
        indent = options['format']['indent']['style']
        if type(options['base'] == str):
            _base = options['base']
        else:
            _base = stringRepeat(indent, options['format']['indent']['base'])
    else:
        options = defaultOptions
        indent = options['format']['indent']['style']
        _base = stringRepeat(indent, options['format']['indent']['base'])
    json = options['format']['json']
    renumber = options['format']['renumber']
    hexadecimal = False if json else options['format']['hexadecimal']
    quotes = 'double' if json else options['format']['quotes']
    escapeless = options['format']['escapeless']
    newline = options['format']['newline']
    space = options['format']['space']
    if options['format']['compact']:
        newline = ''
        space = ''
        indent = ''
        _base = ''
    parentheses = options['format']['parentheses']
    semicolons = options['format']['semicolons']
    safeConcatenation = options['format']['safeConcatenation']
    directive = options['directive']
    parse = None if json else options['parse']
    sourceMap = options['sourceMap']
    sourceCode = options['sourceCode']
    preserveBlankLines = options['format']['preserveBlankLines'] and sourceCode is not None
    extra = options

    if sourceMap:
        if not exports['browser']:
            # Todo
            # SourceNode = require('source-map').SourceNode
            pass
        else:
            # Todo
            # SourceNode = global.sourceMap.SourceNode;
            pass
    result = generateInternal(node)
    return str(result)
    # if not sourceMap:
    #     pair = {'code': str(result), 'map': None}
    #     return pair if options.sourceMapWithCode else pair['code']
    #
    # pair = result.toStringWithSourceMap({
    #     file: options.file,
    #     sourceRoot: options.sourceMapRoot
    # });
    #
    #     if (options.sourceContent) {
    #     pair.map.setSourceContent(options.sourceMap,
    #                               options.sourceContent);
    #
    # }
    #
    # if (options.sourceMapWithCode) {
    # return pair;
    # }

    # return pair.map.toString();
