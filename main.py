import yara

def scan_file(file_rules,filetoscan):
    rules = yara.compile(file_rules)
    result = rules.match(filetoscan)
    print(result)

if __name__ == '__main__':
    name_rules = input("Add the name of the file with the rules: ")
    name_file = input("Add the file name to scan: ")
    scan_file(name_rules, name_file)