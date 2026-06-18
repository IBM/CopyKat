
with open("fprintf.locations", "r") as f:
    while True:
        folder = f.readline()
        if  not folder:
            break
        folder = folder.split('/')[0]

        address = f.readline()
        if not address:
            break
        address = address.split(' ')[3]

        with open(folder+'/s2e-config.lua', 'r') as config:
            file = config.readlines()

        with open(folder+'/s2e-config.lua', 'w') as config:
            for  l in file:
                if "pluginsConfig.kdo" in l:
                    config.write(l)
                    config.write("    kdo_fprintf_location = {},\n".format(address))
                else:
                    config.write(l)


