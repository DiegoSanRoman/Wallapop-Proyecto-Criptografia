import os
import json

class JsonHandler:
    def __init__(self):
        pass

    def read_json(self, filename):
        if os.path.exists(filename):
            with open(filename, 'r', encoding="utf-8") as file:
                try:
                    data = list(json.load(file))
                except json.JSONDecodeError:
                    data = []
        else:
            data = []
        return data

    def write_json(self, filename, data):
        with open(filename, 'w', encoding="utf-8") as file:
            json.dump(data, file, indent=4)

    def modify_json(self, filename, modify_function):
        data = self.read_json(filename)
        modified_data = modify_function(data)
        self.write_json(filename, modified_data)