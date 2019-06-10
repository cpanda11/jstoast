from .models import *
from rest_framework import serializers


class ScriptParseSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScriptParse
        fields = ('input_js', 'jsx', 'range', 'loc', 'tolerant', 'tokens', 'comment')


class AstParseSerializer(serializers.ModelSerializer):
    class Meta:
        model = AstParse
        fields = ('input_ast',)


class JsParseSerializer(serializers.ModelSerializer):
    ntime = serializers.IntegerField(default=1)
    second_limit = serializers.IntegerField(default=60)

    class Meta:
        model = GenerateNewScript
        fields = ('input_js', 'ntime', 'second_limit',)

