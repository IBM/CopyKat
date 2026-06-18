import json
import argparse

def main ():
    parser = argparse.ArgumentParser()
    parser.add_argument("filename")
    parser.add_argument("entry")
    args = parser.parse_args()

    print(args.filename)
    print(args.entry)

    f = open(args.filename)
    data = json.load(f)

    for entry in data:
        for key, val in entry.items():
            if key == "id":
                if val.startswith(args.entry):
                    out = open("/home/s2e/cco_s2e/projects/{}/{}.{}".format(args.entry, args.entry, "output"), "w")
                    json.dump(entry, out, indent=4)
                    out.close()
                    return



if __name__ == "__main__":
    main()
