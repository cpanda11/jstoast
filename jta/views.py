import json
from copy import deepcopy

from rest_framework.generics import CreateAPIView, ListAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from .serializer import *
from .models import *

import esprima
from astconv.astconv import generate
from jsml.js_ast_templates import js_templates
import os


class ScriptParseViewSet(CreateAPIView):
    queryset = ScriptParse.objects.all()
    serializer_class = ScriptParseSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            input_js = serializer.data.get('input_js')
            option = {'jsx': serializer.data.get('jsx'), 'range': serializer.data.get('range'),
                      'loc': serializer.data.get('loc'), 'tolerant': serializer.data.get('tolerant'),
                      'tokens': serializer.data.get('tokens'), 'comment': serializer.data.get('comment')}
            output_ast = esprima.parseScript(
                input_js, option
            ).toDict()

            try:
                ScriptParse.objects.create(
                    input_js=input_js, output_ast=json.dumps(output_ast), jsx=option['jsx'],
                    range=option['range'], loc=option['loc'], tolerant=option['tolerant'],
                    tokens=option['tokens'], comment=option['comment']

                )
            except Exception as e:
                print(e)

            return Response({
                'out_ast': output_ast
            })
        else:
            Response({
                'status': 0,
                'message': 'incorrect data',
                'data': []
            })


class AstParseViewSet(APIView):
    serializer_class = AstParseSerializer

    def get_serializer(self):
        return AstParseSerializer()

    def post(self, request, *args, **kwargs):
        try:
            ast = request.data['input_ast']
            output_js = generate(json.loads(ast))
            return Response({
                'output_js': output_js
            })
        except Exception as e:
            Response({
                'status': 0,
                'message': 'incorrect data',
                'data': []
            })


class GenerateNewJs(CreateAPIView):
    serializer_class = JsParseSerializer
    paginate_by = 10
    paginate_by_param = 'page_size'
    max_paginate_by = 20

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            input_js = serializer.data.get('input_js')
            ntime = serializer.data.get('ntime')
            output_ast = esprima.parseScript(input_js).toDict()

            # try:
            #     ScriptParse.objects.create(
            #         input_js=input_js, output_ast=json.dumps(output_ast), jsx=False,
            #         range=False, loc=False, tolerant=False, tokens=False, comment=False
            #     )
            # except Exception as e:
            #     print(e)

            jt = js_templates(reserved_words='./jsml/js_reserved_words.txt')

            if not os.path.isfile('./jsml/js_types_templates.pkl') or \
                    not os.path.isfile('./jsml/js_program_templates.pkl'):
                return Response({
                    'status': 0,
                    'message': 'Doesn\'t exist DB for Machine learning',
                    'data': []
                })

            t = jt.convert_template(output_ast)
            new_asts = []

            import time
            t_end = time.time() + serializer.data.get('second_limit')
            print(t_end)
            for i in range(ntime):
                print(time.time())
                print('ntime -- ', i)
                if time.time() > t_end:
                    break
                if i == 0:
                    jt.generate_ast_template(t)
                    new_tt = deepcopy(t)
                    print(new_tt)
                    new_asts.append(new_tt)
                else:
                    jt.generate_ast_template(jt.generate_random_program(t))
                    new_tt = deepcopy(t)
                    print(new_tt)
                    new_asts.append(new_tt)

            new_js = []
            for ast in new_asts:
                print(ast)
                try:
                    new_js.append(generate(ast))
                except Exception as e:
                    print(e)
            print("success holding js.")
            return Response({
                'out_new_js': new_js
            })
        else:
            Response({
                'status': 0,
                'message': 'incorrect data',
                'data': []
            })


class RebuildMLViewSet(APIView):
    def get(self, request, *args, **kwargs):
        try:
            jt = js_templates(reserved_words='./jsml/js_reserved_words.txt')
            print("Rebuilding ML...")
            if jt.learn_templates(database="./db.sqlite3", convert_values=True) is False:
                return Response({
                    'status': 0,
                    'message': 'Doesn\'t exist DB for Machine learning',
                    'data': []
                })
            else:
                return Response({
                    'status': 1,
                    'message': 'Success rebuilding for Machine learning',
                    'data': []
                })
        except Exception as e:
            Response({
                'status': 0,
                'message': 'incorrect data',
                'data': []
            })

