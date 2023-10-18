import os
import importlib.util

ERROR_DOC_FILE_PATH = "./error_codes.md"
framworkdir = '../vault_sdk/framework'
bridgedir = '../vault_sdk/bridges'
ERROR_DOC_TITLE = '# Error codes'
ERROR_DOC_SUMMARY = 'This document lists various error codes returned by vault bridge SDK and provides information on the corrective action.'

def openFile(file_path, operation):
    f = open(file_path, operation)    
    return f


def load_from_file(filepath):
    module_name = 'error_codes'
    spec = importlib.util.spec_from_file_location( module_name, filepath)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module

def writeToErrorDoc(errorCodeMod, f):
    f.write(f"### {errorCodeMod.COMPONENT_TYPE} {errorCodeMod.COMPONENT_NAME} - Error codes\n")
    for key1, value1 in errorCodeMod.COMPONENT_EXCEPTIONS.items():
        f.write(f"#### {key1}:\n")
        f.write(f"\n|  | **Description** ")
        f.write(f"\n|--|--")
        f.write(f"\n|**Code** | {key1}")
        for key2, value2 in value1.items():
            if key2 == 'reason':
                f.write(f"\n|**Reason** | {value2}")
            if key2 == 'action':
                f.write(f"\n|**Action** | {value2}")
        f.write(f"\n")
    f.write(f"\n\n")

def generateErrorDoc():
    f = openFile(ERROR_DOC_FILE_PATH, "w")
    f.write(f"{ERROR_DOC_TITLE} \n")
    f.write(f"{ERROR_DOC_SUMMARY} \n")

    errorCodesLocations = [framworkdir,bridgedir]

    for loc in errorCodesLocations:
        for subdir, dir, files in os.walk(loc):
            dir.sort()
            for file in files:
                if file == 'error_codes.py':
                    print(os.path.join(subdir,file), ",subdir=",subdir)
                    m = load_from_file(os.path.join(subdir,file))
                    print('Adding error codes to the doc for ', m.COMPONENT_TYPE)
                    writeToErrorDoc(m,f)

def main():
    generateErrorDoc()

if __name__ == "__main__":
    main()
