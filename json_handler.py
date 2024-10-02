import os
import json

class JsonHandler:
    def __init__(self):
        pass

    def read_json(self, filename):
        with open(f'json_files/{filename}', 'r') as file:
            data = json.load(file)
        return data

    def write_json(self, filename, data):
        with open(f'json_files/{filename}', 'w') as file:
            json.dump(data, file, indent=4)

    def modify_json(self, filename, modify_function):
        filename = self.base_path + filename
        data = self.read_json(filename)
        modified_data = modify_function(data)
        self.write_json(filename, modified_data)