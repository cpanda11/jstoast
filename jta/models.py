from django.db import models


class ScriptParse(models.Model):
    input_js = models.TextField(null=True, blank=True)
    output_ast = models.TextField(null=True, blank=True)
    jsx = models.BooleanField(default=False)
    range = models.BooleanField(default=False)
    loc = models.BooleanField(default=False)
    tolerant = models.BooleanField(default=False)
    tokens = models.BooleanField(default=False)
    comment = models.BooleanField(default=False)


class AstParse(models.Model):
    input_ast = models.TextField(null=True, blank=True)
    output_js = models.TextField(null=True, blank=True)


class GenerateNewScript(models.Model):
    input_js = models.TextField(null=True, blank=True)
    output_ast = models.TextField(null=True, blank=True)
