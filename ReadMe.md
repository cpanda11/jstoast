# ASTs Generator

The main goal for this project is generating a valid AST to translate them to javascript code later.

## Approach

First we used the avilable dataset which represent more than 1000 records of ASTs to learn ASTs basic templates. Later we tries to learn the possible replacments for AST blocks or sub-tree between each others by learning the possible templates for each sub-tree in AST (example: what are the possible templates to replace a 'WhileStatement').

## Prerequisites
the only requirments for this project is python 3+, no need to install any additional library.


## Running the code

###1- To learn template use the function "learn_templates(database , convert_values)":
this function take a url to sqlite database that contains js ASTs and learn templates from it
the convert_numbers parameter for changing variables values to static form.
This function will learn the templates and save them in js_templates.pkl file.

```
jt = js_templates(reserved_words='js_reserved_words.txt')

jt.learn_templates(database ="./jta_scriptparse_revise.db" ,convert_values=True)
```

###2- To generate new AST you just need to call "generate_ast(templates_model)":
this function create ast from learnt templates for AST and block and sub-trees and set parameters values randomly


```
jt.generate_ast(templates_model ='./js_templates.pkl')
```

and this is an example of the generated ASTs:

```
'{"type": "Program", "sourceType": "script", "body": [{"type": "ExpressionStatement", "expression": {"type": "CallExpression", "callee": {"type": "MemberExpression", "computed": false, "object": {"type": "MemberExpression", "computed": false, "object": {"type": "MemberExpression", "computed": false, "object": {"type": "Identifier", "name": "IK8WTW20FQ7"}, "property": {"type": "Identifier", "name": "IYT4SOFW379"}}, "property": {"type": "Identifier", "name": "IZ6PSOGS6V7"}}, "property": {"type": "Identifier", "name": "I12J9W56DBL"}}, "arguments": [{"type": "Literal", "value": true, "raw": "True"}]}}, {"type": "ExpressionStatement", "expression": {"type": "CallExpression", "callee": {"type": "Identifier", "name": "IIG28WG20YS"}, "arguments": []}}]}'
```

Note that each time you call this function you will get different results. since the systrem will generate new AST for each call.

