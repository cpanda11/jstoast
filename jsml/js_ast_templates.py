# coding: utf-8

# In[1]:


import sqlite3
from sqlite3 import Error
import json
import random
import string
import pprint, pickle
import os


# # class to handle database connections and queries

# In[2]:


class sqliteDatabase():

    def __init__(self, url):
        self.conn = self.create_connection(url)

    def create_connection(self, db_file):
        """ create a database connection to the SQLite database
            specified by the db_file
        :param db_file: database file
        :return: Connection object or None
        """
        try:
            conn = sqlite3.connect(db_file)
            return conn
        except Error as e:
            print(e)

        return None

    def create_db(self):
        conn = self.conn
        c = conn.cursor()

        # Create table
        c.execute('''CREATE TABLE IF NOT EXISTS jta_scriptparse (
            id integer NOT NULL PRIMARY KEY AUTOINCREMENT,
            input_js text,
            output_ast text,
            comment bool NOT NULL,
            jsx bool NOT NULL,
            loc bool NOT NULL,
            range bool NOT NULL,
            tokens bool NOT NULL,
            tolerant bool NOT NULL
        );''')

        with open('jta_scriptparse_revise_modified.sql', 'rb') as f:
            #     print(f.read().decode('utf-8').split(';'))
            for l in f.read().decode('utf-8').split('INSERT INTO')[1:]:
                l = 'INSERT INTO' + l
                #         print('ll :' , l)
                try:

                    # Insert a row of data
                    c.execute(l)

                    # Save (commit) the changes
                    conn.commit()

                    print("finish successfuly")
                except sqlite3.OperationalError as e:
                    print(e)
                    print('-' * 50)
                    print(l)
                    break
                except Exception as e:
                    print(e)
                    print('-' * 50)
                    print(l)
                    break

    def select_all_tasks(self):
        conn = self.conn
        """
        Query all rows in the tasks table
        :param conn: the Connection object
        :return:
        """
        cur = conn.cursor()
        cur.execute("SELECT * FROM jta_scriptparse")

        rows = cur.fetchall()

        return rows

    def select_row_by_id(self, id):
        conn = self.conn
        """
        Query tasks by priority
        :param conn: the Connection object
        :param priority:
        :return:
        """
        cur = conn.cursor()
        cur.execute("SELECT * FROM jta_scriptparse WHERE id=?", (id,))

        rows = cur.fetchall()

        return rows[0]


# # class to learn templates from js ASTs :
# ## main functions:
# ### 1- learn_templates(database , convert_values):
# #### this function take a url to sqlite database that contains js ASTs and learn templates from it 
# #### the convert_numbers parameter for changing variables values to static form
# 
# ### 2- generate_ast(templates_model):
# #### this function create ast from random template and set parameters values randomly

# In[3]:


class js_templates():

    def __init__(self, reserved_words='./js_reserved_words.txt'):
        self.reserved_words_url = reserved_words

    def get_reserved_words(self):
        RESERVED_WORDS = []
        with open(self.reserved_words_url, 'r') as f:
            for l in f:
                RESERVED_WORDS.append(l.split('\n')[0])
        RESERVED_WORDS = set(RESERVED_WORDS)
        return RESERVED_WORDS

    def convert_template(self, inDict, template_vars={}, conver_numbers=True):
        if isinstance(inDict, dict):
            for k in inDict.keys():
                inDict[k] = self.convert_template(inDict[k], template_vars, conver_numbers)

            if inDict.get('type') != None and inDict.get('name') != None:
                if inDict['type'] == 'Identifier':
                    #                         print("change var :" , inDict['id']['name'])
                    if inDict['name'] in self.get_reserved_words():
                        pass
                    elif inDict['name'] not in template_vars:
                        rand = 'I' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
                        template_vars[inDict['name']] = rand
                        inDict['name'] = rand

                    else:
                        inDict['name'] = template_vars[inDict['name']]


            elif conver_numbers:
                if inDict.get('type') != None and inDict.get('value') != None and inDict.get('raw') != None:
                    if inDict['type'] == "Literal":
                        temp = str(type(inDict['value']))
                        #                         if type(inDict['value']) == int:
                        #                             temp = str(float)
                        inDict['value'] = temp
                        inDict['raw'] = temp


        elif isinstance(inDict, list):
            for i in range(len(inDict)):
                inDict[i] = self.convert_template(inDict[i], template_vars, conver_numbers)

        return inDict

    def merge_two_dicts(self, x, y):
        """Given two dicts, merge them into a new dict as a shallow copy."""
        for k in y:
            # print(k)
            if k in x:
                x[k].extend(y[k])
            else:
                x[k] = y[k]
        return x

    def get_types_templates(self, inDict, all_type_ids):
        types = {}
        if isinstance(inDict, dict):
            if inDict.get('type'):
                if inDict.get('type') in all_type_ids:
                    if types.get(inDict.get('type')):
                        types[inDict.get('type')].append(inDict)
                    else:
                        types[inDict.get('type')] = [inDict]

            for k in inDict.keys():
                types = self.merge_two_dicts(types, self.get_types_templates(inDict[k], all_type_ids))

        elif isinstance(inDict, list):
            for i in range(len(inDict)):
                types = self.merge_two_dicts(types, self.get_types_templates(inDict[i], all_type_ids))

        return types

    def get_all_types_templates(self, templates, all_type_ids):
        database = "./db.sqlite3"

        all_typess = {}

        for row in templates:
            counter = 0
            temp_ids = []
            row_ast = json.loads(row[1])

            temps = self.get_types_templates(row_ast, all_type_ids)

            all_typess = self.merge_two_dicts(all_typess, temps)

        return all_typess

    def get_ids_from_template(self, inDict):
        ids = []
        if isinstance(inDict, dict):
            if inDict.get('type'):
                ids.append(inDict.get('type'))

            for k in inDict.keys():
                ids.extend(self.get_ids_from_template(inDict[k]))

        elif isinstance(inDict, list):
            for i in range(len(inDict)):
                ids.extend(self.get_ids_from_template(inDict[i]))

        return set(ids)

    def get_all_ast_ids(self, database="./db.sqlite3"):

        data = sqliteDatabase(database)

        all_ids = []
        rows = data.select_all_tasks()
        for row in rows:
            row_ast = json.loads(row[2])
            tid = self.get_ids_from_template(row_ast)
            all_ids.extend(tid)
        return set(all_ids)

    def convert_all_templates(self, database="./db.sqlite3", conver_numbers=True):

        all_tempaltes = []

        data = sqliteDatabase(database)
        print("Query all ...")
        rows = data.select_all_tasks()
        for row in rows:
            row_ast = json.loads(row[2])
            template = self.convert_template(row_ast, template_vars={}, conver_numbers=conver_numbers)
            all_tempaltes.append((row[0], json.dumps(template)))

        return all_tempaltes

    def generate_ast_template(self, inDict, template_vars={}):
        if isinstance(inDict, dict):
            for k in inDict.keys():
                inDict[k] = self.generate_ast_template(inDict[k], template_vars)

            if inDict.get('type') != None and inDict.get('name') != None:
                if inDict['type'] == 'Identifier':
                    #                         print("change var :" , inDict['id']['name'])
                    if inDict['name'] in self.get_reserved_words():
                        pass

                    elif inDict['name'] not in template_vars:
                        rand = 'I' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
                        template_vars[inDict['name']] = rand
                        inDict['name'] = rand

                    else:
                        inDict['name'] = template_vars[inDict['name']]

            elif inDict.get('type') != None and inDict.get('value') != None and inDict.get('raw') != None:
                if inDict['type'] == "Literal":
                    #                     print("change \t:",inDict['value'])
                    if inDict['value'] == str(float):
                        rand = random.uniform(1.0, 100.0)
                        inDict['value'] = rand
                        inDict['raw'] = str(rand)

                    if inDict['value'] == str(int):
                        rand = random.randint(0, 100)
                        inDict['value'] = rand
                        inDict['raw'] = str(rand)

                    elif inDict['value'] == str(str):
                        rand = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
                        inDict['value'] = rand
                        inDict['raw'] = "\"" + rand + "\""

                    elif inDict['value'] == str(bool):
                        rand = bool(random.getrandbits(1))
                        inDict['value'] = rand
                        inDict['raw'] = str(rand)


        elif isinstance(inDict, list):
            for i in range(len(inDict)):
                inDict[i] = self.generate_ast_template(inDict[i], template_vars)

        return inDict

    def generate_random_program(self, inDict):

        all_type_ids, all_types = [], {}
        with open('./jsml/js_types_templates.pkl', 'rb') as f:
            all_type_ids, all_types = pickle.load(f)
        if all_types == {}:
            print("error loading templates")
            return None

        if isinstance(inDict, dict):
            if inDict.get('body'):
                if isinstance(inDict['body'], list):
                    for i in range(len(inDict['body'])):
                        if isinstance(inDict['body'][i], dict):
                            if inDict['body'][i].get('type'):
                                if all_types.get(inDict['body'][i].get('type')):
                                    rand = random.randint(0, len(all_types[inDict['body'][i].get('type')]) - 1)
                                    inDict['body'][i] = all_types[inDict['body'][i].get('type')][rand]

                                else:
                                    print("ERROR6")
                            else:
                                print("ERROR5")
                        else:
                            print("ERROR4")
                    return inDict
                else:
                    print("ERROR3")
            else:
                print("ERROR2")
        else:
            print("ERROR1")

        return None

    def learn_templates(self, database="./db.sqlite3", convert_values=False):
        if not os.path.isfile(database):
            print("database not found !!!")
            return False
        templates = self.convert_all_templates(database, conver_numbers=convert_values)
        print('number of ASTs: \t', len([t[1] for t in templates]))
        print('number of program templates learned: \t', len(set([t[1] for t in templates])))

        url = './jsml/js_program_templates.pkl'
        url2 = './jsml/js_types_templates.pkl'

        with open(url, 'wb') as f:
            pickle.dump(templates, f)

        print('-' * 50)
        print('\n')

        all_type_ids = self.get_all_ast_ids()
        all_types = self.get_all_types_templates(templates, all_type_ids)

        with open(url2, 'wb') as f:
            pickle.dump((all_type_ids, all_types), f)

        print("\n")

        print('number of types templates learned: \t', len(all_types))
        for k in all_types:
            print(k, "\t", len(all_types[k]))
        print('-' * 50)
        print('\n')

        print('number of reserved words :\t', len(self.get_reserved_words()))

        print('-' * 50)
        print('\n')
        print('learned model saved to: \n', url, "\n", url2)
        return True

    def generate_ast(self, templates_model='./jsml/js_templates.pkl'):
        templates = []

        if os.path.isfile(templates_model):
            with open(templates_model, 'rb') as f:
                templates = pickle.load(f)
        else:
            print("model not found !!!")
            templates_model = './jsml/js_templates.pkl'
            database = "./db.sqlite3"
            if os.path.isfile(database):
                self.learn_templates(database=database, convert_values=True)
            else:
                print("database not found !!!")

        index = random.randint(0, len(templates) - 1)

        template = templates[index]

        templ = json.loads(template[1])
        rand_ast = self.generate_ast_template(self.generate_random_program(templ))

        return json.dumps(rand_ast)


