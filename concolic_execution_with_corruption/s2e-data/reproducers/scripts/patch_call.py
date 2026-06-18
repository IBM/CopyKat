import r2pipe

def patch_file(input_file, address):
    r2 = r2pipe.open(input_file, flags=['-w'])
    print(r2.cmd("s " + address))
    r2.cmd("wx 9090909090")
    # print(r2.cmd("pd 10"))
    # r2.cmd("wc")

def read_locations (file):
    with open(file, "r") as f:
        while True:
            folder = f.readline()
            if  not folder:
                break
            folder = folder.split('/')[0]

            address = f.readline()
            if not address:
                break
            address = address.split(' ')[3]

            # print(address)
            patch_file(folder+"/repro-"+folder, address)

read_locations("fprintf.locations")
read_locations("fclose.locations")
read_locations("fopen.locations")
